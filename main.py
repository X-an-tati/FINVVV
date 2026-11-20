from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import hashlib
import os
import secrets
import json
from datetime import datetime, timedelta

from database import get_db_connection, init_db, ensure_default_staff
from security import hash_password, verify_password, encrypt_data, decrypt_data

app = FastAPI(title="SecureFin Core Enterprise", version="7.0-FINAL")

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "ALLOWED_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:8000,http://localhost:8000,null",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

THREAT_ORIGINS = [
    {"ip": "185.220.101.42", "geo": "Amsterdam, NL (Tor Exit Node)", "risk": "CRITICAL"},
    {"ip": "45.155.205.89", "geo": "Frankfurt, DE (Anonymous VPN)", "risk": "HIGH"},
    {"ip": "91.240.118.17", "geo": "Bucharest, RO (Botnet Proxy)", "risk": "CRITICAL"},
    {"ip": "103.253.41.98", "geo": "Singapore, SG (Cloud Datacenter)", "risk": "HIGH"},
    {"ip": "194.26.135.21", "geo": "Riga, LV (Suspicious ASN)", "risk": "HIGH"},
]


def is_system_locked(cursor) -> bool:
    cursor.execute("SELECT value FROM system_settings WHERE key = 'system_lockdown'")
    row = cursor.fetchone()
    return bool(row and row["value"] == "1")


def set_system_locked(cursor, locked: bool):
    cursor.execute(
        """
        INSERT INTO system_settings (key, value, updated_at)
        VALUES ('system_lockdown', ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        """,
        ("1" if locked else "0",),
    )


def compute_log_hash(prev_hash: str, user_id: Optional[int], action: str, details: str) -> str:
    raw = f"{prev_hash}|{user_id}|{action}|{details}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_audit_log(cursor, user_id: Optional[int], action: str, details: str):
    cursor.execute("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    prev_hash = last_row["record_hash"] if last_row else "GENESIS_BLOCK"
    rec_hash = compute_log_hash(prev_hash, user_id, action, details)

    cursor.execute(
        """
        INSERT INTO audit_logs (user_id, action, details, prev_hash, record_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, action, details, prev_hash, rec_hash),
    )


def create_incident(cursor, incident_type: str, severity: str, summary: str, source_ip: Optional[str] = None):
    cursor.execute(
        """
        INSERT INTO incidents (incident_type, severity, status, summary, source_ip)
        VALUES (?, ?, 'OPEN', ?, ?)
        """,
        (incident_type, severity, summary, source_ip),
    )


def resolve_session_user(cursor, authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None
    cursor.execute(
        """
        SELECT u.id, u.username, u.role
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def require_authenticated_user(cursor, authorization: Optional[str], allowed_roles: Optional[tuple] = None):
    user = resolve_session_user(cursor, authorization)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="🔒 Требуется авторизация (войдите в систему или подайте заявку на открытие счёта).",
        )
    if allowed_roles and user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"⛔ Доступ запрещён для роли '{user['role']}' ({user['username']}). Требуется: {', '.join(allowed_roles)}.",
        )
    return user


def issue_otp_in_db(cursor, user_id: int) -> str:
    code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO otp_codes (user_id, code, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET code = excluded.code, expires_at = excluded.expires_at
        """,
        (user_id, code, expires_at),
    )
    return code


def verify_and_consume_otp(cursor, user_id: int, provided_code: str) -> bool:
    cursor.execute("SELECT code, expires_at FROM otp_codes WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return False
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if row["expires_at"] < now_str:
        cursor.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
        return False
    if not secrets.compare_digest(row["code"], provided_code.strip()):
        return False
    cursor.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
    return True


@app.on_event("startup")
def startup_event():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("BEGIN IMMEDIATE;")
    ensure_default_staff(cursor)
    cursor.execute("COMMIT;")
    cursor.close()
    conn.close()


class ApplicationCreateRequest(BaseModel):
    username: str
    password: str
    requested_balance: float = 300000.0
    requested_limit: float = 300000.0


class ClientOpenRequest(BaseModel):
    username: str
    password: str
    initial_balance: float = 300000.0
    daily_limit: float = 300000.0


class UserLogin(BaseModel):
    username: str
    password: str


class LimitUpdateRequest(BaseModel):
    user_id: int
    daily_limit: float


class TransferRequest(BaseModel):
    sender_user_id: int
    receiver_user_id: int
    amount: float
    otp_code: Optional[str] = None
    idempotency_key: Optional[str] = None
    is_red_team: Optional[bool] = False


class OTPRequest(BaseModel):
    user_id: int
    amount: float


@app.get("/")
def root():
    conn = get_db_connection()
    cursor = conn.cursor()
    locked = is_system_locked(cursor)
    cursor.execute("SELECT COUNT(*) as cnt FROM blocked_ips")
    blocked_ips_count = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'OPEN'")
    open_incidents = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM account_applications WHERE status = 'PENDING'")
    pending_apps = cursor.fetchone()["cnt"]
    cursor.close()
    conn.close()

    return {
        "project": "SecureFin Core Enterprise",
        "status": "ARMED & OPERATIONAL",
        "system_lockdown": locked,
        "open_incidents": open_incidents,
        "pending_applications": pending_apps,
        "persisted_blocked_ips_in_db": blocked_ips_count,
    }


@app.post("/applications", summary="Подача заявки клиента на открытие счёта (статус PENDING)")
def create_account_application(app_req: ApplicationCreateRequest):
    clean_username = app_req.username.strip()
    if len(clean_username) < 3 or len(app_req.password) < 4:
        raise HTTPException(status_code=400, detail="Логин должен быть от 3 символов, пароль — от 4 символов.")
    if app_req.requested_balance < 0 or app_req.requested_limit <= 0:
        raise HTTPException(status_code=400, detail="Некорректная сумма депозита или дневного лимита.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        cursor.execute("SELECT id FROM users WHERE username = ?", (clean_username,))
        if cursor.fetchone():
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="Аккаунт с таким логином уже существует в банке")

        cursor.execute(
            "SELECT id, status FROM account_applications WHERE applicant_username = ?",
            (clean_username,),
        )
        existing_app = cursor.fetchone()
        if existing_app:
            if existing_app["status"] == "PENDING":
                cursor.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail="Заявка с таким логином уже отправлена и ожидает оператора")
            if existing_app["status"] == "APPROVED":
                cursor.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail="Заявка уже одобрена — войдите через форму входа")
            cursor.execute("DELETE FROM account_applications WHERE id = ?", (existing_app["id"],))

        pwd_hash = hash_password(app_req.password)
        cursor.execute(
            """
            INSERT INTO account_applications (applicant_username, password_hash, requested_balance, requested_limit, status)
            VALUES (?, ?, ?, ?, 'PENDING')
            """,
            (clean_username, pwd_hash, app_req.requested_balance, app_req.requested_limit),
        )
        app_id = cursor.lastrowid
        write_audit_log(
            cursor,
            None,
            "ACCOUNT_APPLICATION_SUBMITTED",
            f"Подана заявка #{app_id} на открытие счёта '{clean_username}' (депозит: {app_req.requested_balance:,.0f} KZT, лимит: {app_req.requested_limit:,.0f} KZT).",
        )
        cursor.execute("COMMIT;")
        return {
            "status": "PENDING",
            "application_id": app_id,
            "applicant_username": clean_username,
            "message": "Заявка отправлена операционисту. После одобрения вы сможете войти под своим логином и паролем.",
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/applications", summary="Список заявок на открытие счёта (OPERATOR / SECURITY_OFFICER)")
def list_applications(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER"))
        cursor.execute(
            """
            SELECT id, applicant_username, requested_balance, requested_limit, status, created_at, reviewed_at
            FROM account_applications
            ORDER BY CASE WHEN status = 'PENDING' THEN 0 ELSE 1 END, id DESC
            """
        )
        return {"status": "success", "applications": [dict(r) for r in cursor.fetchall()]}
    finally:
        cursor.close()
        conn.close()


@app.post("/applications/{app_id}/approve", summary="Одобрить заявку и открыть клиентский счёт (OPERATOR / SECURITY_OFFICER)")
def approve_application(app_id: int, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER"))

        cursor.execute("SELECT * FROM account_applications WHERE id = ?", (app_id,))
        app_row = cursor.fetchone()
        if not app_row:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=404, detail="Заявка не найдена")
        if app_row["status"] != "PENDING":
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail=f"Заявка уже обработана (статус: {app_row['status']})")

        cursor.execute("SELECT id FROM users WHERE username = ?", (app_row["applicant_username"],))
        if cursor.fetchone():
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")

        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'CLIENT')",
            (app_row["applicant_username"], app_row["password_hash"]),
        )
        client_user_id = cursor.lastrowid

        encrypted_bal = encrypt_data(str(app_row["requested_balance"]))
        cursor.execute(
            "INSERT INTO accounts (user_id, encrypted_balance, daily_limit) VALUES (?, ?, ?)",
            (client_user_id, encrypted_bal, app_row["requested_limit"]),
        )

        cursor.execute(
            """
            UPDATE account_applications
            SET status = 'APPROVED', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (actor["id"], app_id),
        )

        write_audit_log(
            cursor,
            actor["id"],
            "APPLICATION_APPROVED",
            f"[{actor['username']} | {actor['role']}] Одобрил заявку #{app_id} и открыл счёт CLIENT '{app_row['applicant_username']}' (ID #{client_user_id}).",
        )
        cursor.execute("COMMIT;")
        return {
            "status": "APPROVED",
            "application_id": app_id,
            "client_user_id": client_user_id,
            "username": app_row["applicant_username"],
        }
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    except Exception as e:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.post("/applications/{app_id}/reject", summary="Отклонить заявку на открытие счёта (OPERATOR / SECURITY_OFFICER)")
def reject_application(app_id: int, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER"))

        cursor.execute("SELECT * FROM account_applications WHERE id = ?", (app_id,))
        app_row = cursor.fetchone()
        if not app_row:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=404, detail="Заявка не найдена")
        if app_row["status"] != "PENDING":
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail=f"Заявка уже обработана (статус: {app_row['status']})")

        cursor.execute(
            """
            UPDATE account_applications
            SET status = 'REJECTED', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (actor["id"], app_id),
        )
        write_audit_log(
            cursor,
            actor["id"],
            "APPLICATION_REJECTED",
            f"[{actor['username']} | {actor['role']}] Отклонил заявку #{app_id} ('{app_row['applicant_username']}').",
        )
        cursor.execute("COMMIT;")
        return {"status": "REJECTED", "application_id": app_id}
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    except Exception as e:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.post("/clients/open", summary="Прямое открытие клиентского счёта сотрудником (OPERATOR / SECURITY_OFFICER)")
def open_client_account(client: ClientOpenRequest, authorization: Optional[str] = Header(default=None)):
    clean_username = client.username.strip()
    if len(clean_username) < 3 or len(client.password) < 4:
        raise HTTPException(status_code=400, detail="Логин должен быть от 3 символов, пароль — от 4 символов.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER"))

        cursor.execute("SELECT id FROM users WHERE username = ?", (clean_username,))
        if cursor.fetchone():
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="Клиент с таким логином уже существует")

        pwd_hash = hash_password(client.password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'CLIENT')",
            (clean_username, pwd_hash),
        )
        client_user_id = cursor.lastrowid

        encrypted_bal = encrypt_data(str(client.initial_balance))
        cursor.execute(
            "INSERT INTO accounts (user_id, encrypted_balance, daily_limit) VALUES (?, ?, ?)",
            (client_user_id, encrypted_bal, client.daily_limit),
        )

        write_audit_log(
            cursor,
            actor["id"],
            "CLIENT_ACCOUNT_OPENED",
            f"[{actor['username']} | {actor['role']}] Открыл клиентский счёт '{clean_username}' (ID #{client_user_id}, депозит: {client.initial_balance:,.0f} KZT, лимит: {client.daily_limit:,.0f} KZT).",
        )
        cursor.execute("COMMIT;")
        return {
            "status": "success",
            "user_id": client_user_id,
            "username": clean_username,
            "role": "CLIENT",
        }
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    except Exception as e:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.post("/auth/login", summary="Вход по логину и паролю с выдачей сессионного токена")
def login(creds: UserLogin):
    clean_username = creds.username.strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        cursor.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (clean_username,),
        )
        user = cursor.fetchone()
        if not user or not verify_password(creds.password, user["password_hash"]):
            cursor.execute(
                "SELECT status FROM account_applications WHERE applicant_username = ?",
                (clean_username,),
            )
            app_row = cursor.fetchone()
            write_audit_log(
                cursor,
                None,
                "LOGIN_FAILED",
                f"Неудачная попытка входа под логином '{clean_username}'.",
            )
            cursor.execute("COMMIT;")
            if app_row and app_row["status"] == "PENDING":
                raise HTTPException(
                    status_code=403,
                    detail="⏳ Ваша заявка на открытие счёта ещё на проверке у операциониста (статус: PENDING).",
                )
            if app_row and app_row["status"] == "REJECTED":
                raise HTTPException(
                    status_code=403,
                    detail="⛔ Заявка на открытие счёта была отклонена операционистом.",
                )
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")

        token = secrets.token_hex(24)
        cursor.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user["id"]))
        write_audit_log(
            cursor,
            user["id"],
            "USER_LOGIN",
            f"Вход в контур: '{user['username']}' (подтверждённая роль: {user['role']}).",
        )
        cursor.execute("COMMIT;")

        return {
            "status": "success",
            "token": token,
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }
    finally:
        cursor.close()
        conn.close()


@app.get("/auth/me", summary="Проверка текущей сессии и роли из БД")
def get_me(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        user = require_authenticated_user(cursor, authorization)
        return {"status": "authenticated", "user": user, "system_lockdown": is_system_locked(cursor)}
    finally:
        cursor.close()
        conn.close()


@app.post("/auth/logout", summary="Завершение сессии")
def logout(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"status": "ok"}
    token = authorization.split(" ", 1)[1].strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        user = resolve_session_user(cursor, authorization)
        if user:
            write_audit_log(cursor, user["id"], "USER_LOGOUT", f"Выход из сессии '{user['username']}' ({user['role']}).")
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        cursor.execute("COMMIT;")
        return {"status": "logged_out"}
    finally:
        cursor.close()
        conn.close()


@app.get("/users", summary="Список аккаунтов (только для сотрудников и аудитора)")
def list_users(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute(
            """
            SELECT u.id, u.username, u.role, a.daily_limit
            FROM users u
            LEFT JOIN accounts a ON a.user_id = u.id
            ORDER BY u.id ASC
            """
        )
        return {"users": [dict(r) for r in cursor.fetchall()]}
    finally:
        cursor.close()
        conn.close()


@app.get("/my-transactions", summary="Транзакции текущего пользователя (отправленные и полученные)")
def get_my_transactions(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        actor = require_authenticated_user(cursor, authorization)
        cursor.execute("SELECT id FROM accounts WHERE user_id = ?", (actor["id"],))
        acc = cursor.fetchone()
        if not acc:
            return {"status": "success", "transactions": []}

        my_acc_id = acc["id"]
        cursor.execute(
            """
            SELECT
                t.id,
                t.amount,
                t.status,
                t.created_at,
                t.sender_account_id,
                t.receiver_account_id,
                u_send.username AS sender_username,
                u_recv.username AS receiver_username
            FROM transactions t
            LEFT JOIN accounts a_send ON t.sender_account_id = a_send.id
            LEFT JOIN users u_send ON a_send.user_id = u_send.id
            LEFT JOIN accounts a_recv ON t.receiver_account_id = a_recv.id
            LEFT JOIN users u_recv ON a_recv.user_id = u_recv.id
            WHERE t.sender_account_id = ? OR t.receiver_account_id = ?
            ORDER BY t.id DESC
            LIMIT 25
            """,
            (my_acc_id, my_acc_id),
        )
        rows = []
        for r in cursor.fetchall():
            item = dict(r)
            item["direction"] = "OUT" if item["sender_account_id"] == my_acc_id else "IN"
            rows.append(item)
        return {"status": "success", "transactions": rows}
    finally:
        cursor.close()
        conn.close()


@app.get("/db-chain-check", summary="Проверка целостности хеш-цепочки и срез VIEW (только персонал/аудит)")
def check_db_chain(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        logs = [dict(row) for row in cursor.fetchall()]

        chain_valid = True
        broken_at_id = None
        expected_prev = "GENESIS_BLOCK"

        for row in logs:
            if row["prev_hash"] != expected_prev:
                chain_valid = False
                broken_at_id = row["id"]
                break
            recalc = compute_log_hash(row["prev_hash"], row["user_id"], row["action"], row["details"])
            if recalc != row["record_hash"]:
                chain_valid = False
                broken_at_id = row["id"]
                break
            expected_prev = row["record_hash"]

        cursor.execute("SELECT * FROM v_transactions_overview ORDER BY tx_id DESC LIMIT 10")
        view_rows = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) as cnt FROM db_trigger_events")
        trigger_events_count = cursor.fetchone()["cnt"]

        return {
            "chain_valid": chain_valid,
            "broken_at_id": broken_at_id,
            "total_audit_rows": len(logs),
            "db_trigger_events_count": trigger_events_count,
            "recent_view_transactions": view_rows,
        }
    finally:
        cursor.close()
        conn.close()


@app.post("/emergency-lockdown", summary="Переключение режима изоляции (только SECURITY_OFFICER)")
def emergency_lockdown(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("SECURITY_OFFICER",))

        new_state = not is_system_locked(cursor)
        set_system_locked(cursor, new_state)

        if new_state:
            write_audit_log(
                cursor,
                actor["id"],
                "DEFCON_1_LOCKDOWN",
                f"[{actor['username']} | {actor['role']}] Активирован аварийный Kill Switch (сохранено в БД). Шлюзы заблокированы.",
            )
            create_incident(
                cursor,
                "EMERGENCY_LOCKDOWN",
                "CRITICAL",
                f"Контур переведён в режим изоляции DEFCON 1 сотрудником {actor['username']}.",
                "LOCAL_CONSOLE",
            )
        else:
            write_audit_log(
                cursor,
                actor["id"],
                "DEFCON_RESTORED",
                f"[{actor['username']} | {actor['role']}] Аварийный режим отключен. Штатная работа восстановлена.",
            )
            cursor.execute(
                """
                UPDATE incidents
                SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP
                WHERE incident_type = 'EMERGENCY_LOCKDOWN' AND status = 'OPEN'
                """
            )
        cursor.execute("COMMIT;")
        return {"status": "SUCCESS", "system_lockdown": new_state, "message": "Статус изоляции изменен."}
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    finally:
        cursor.close()
        conn.close()


@app.post("/update-limit", summary="Изменение дневного лимита счёта (OPERATOR / SECURITY_OFFICER)")
def update_account_limit(req: LimitUpdateRequest, authorization: Optional[str] = Header(default=None)):
    if req.daily_limit <= 0:
        raise HTTPException(status_code=400, detail="Дневной лимит должен быть больше нуля")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER"))

        cursor.execute("SELECT id FROM accounts WHERE user_id = ?", (req.user_id,))
        acc = cursor.fetchone()
        if not acc:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=404, detail="Счёт пользователя не найден")

        cursor.execute("UPDATE accounts SET daily_limit = ? WHERE user_id = ?", (req.daily_limit, req.user_id))
        write_audit_log(
            cursor,
            actor["id"],
            "DAILY_LIMIT_UPDATED",
            f"[{actor['username']} | {actor['role']}] Установил лимит {req.daily_limit:,.0f} KZT для User ID #{req.user_id}.",
        )
        cursor.execute("COMMIT;")
        return {"status": "SUCCESS", "user_id": req.user_id, "daily_limit": req.daily_limit}
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    finally:
        cursor.close()
        conn.close()


@app.get("/account/{user_id}", summary="Получить баланс и дневной лимит (клиент видит только свой счёт)")
def get_account_balance(user_id: str, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        actor = require_authenticated_user(cursor, authorization)
        cursor.execute(
            """
            SELECT a.id, a.user_id, a.encrypted_balance, a.currency, a.daily_limit, u.username, u.role
            FROM accounts a
            JOIN users u ON a.user_id = u.id
            WHERE CAST(a.user_id AS TEXT) = ? OR CAST(a.id AS TEXT) = ? OR u.username = ?
            """,
            (user_id, user_id, user_id),
        )

        account = cursor.fetchone()
        if not account:
            return {"status": "not_found", "message": f"Счет '{user_id}' не найден", "balance": 0.0}

        if actor["role"] == "CLIENT" and account["user_id"] != actor["id"]:
            raise HTTPException(
                status_code=403,
                detail="⛔ Доступ запрещён: клиент может просматривать только свой собственный счёт.",
            )

        cursor.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS spent_today
            FROM transactions
            WHERE sender_account_id = ? AND status = 'SUCCESS' AND date(created_at) = date('now')
            """,
            (account["id"],),
        )
        spent_today = float(cursor.fetchone()["spent_today"])
        decrypted_balance = float(decrypt_data(account["encrypted_balance"]))

        return {
            "status": "success",
            "account_id": account["id"],
            "user_id": account["user_id"],
            "username": account["username"],
            "role": account["role"],
            "balance": decrypted_balance,
            "daily_limit": account["daily_limit"],
            "spent_today": spent_today,
            "remaining_daily_limit": max(0.0, account["daily_limit"] - spent_today),
            "currency": account["currency"],
            "raw_cipher_preview": account["encrypted_balance"][:28] + "...",
            "security_status": "ENCRYPTED_AT_REST",
        }
    finally:
        cursor.close()
        conn.close()


@app.post("/request-otp")
def request_otp(req: OTPRequest, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization)
        if actor["role"] == "CLIENT" and actor["id"] != req.user_id:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=403, detail="Нельзя запрашивать OTP для чужого счёта")
        code = issue_otp_in_db(cursor, req.user_id)
        cursor.execute("COMMIT;")
        return {"status": "OTP_SENT", "otp_code": code, "ttl_seconds": 300}
    finally:
        cursor.close()
        conn.close()


@app.post("/transfer", summary="Атомарный перевод средств с проверкой роли, идемпотентностью, лимитом, Anti-Fraud и 2FA")
def transfer_funds(transfer: TransferRequest, request: Request, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN IMMEDIATE;")

        if is_system_locked(cursor):
            cursor.execute("ROLLBACK;")
            raise HTTPException(
                status_code=403,
                detail="🚨 СИСТЕМА В РЕЖИМЕ ИЗОЛЯЦИИ (DEFCON 1). Транзакции заблокированы.",
            )

        if transfer.is_red_team:
            origin = THREAT_ORIGINS[secrets.randbelow(len(THREAT_ORIGINS))]
            actor = {"id": None, "username": "EXTERNAL_RED_TEAM", "role": "ATTACKER"}
        else:
            actor = require_authenticated_user(
                cursor,
                authorization,
                allowed_roles=("OPERATOR", "SECURITY_OFFICER", "CLIENT"),
            )
            if actor["role"] == "CLIENT" and actor["id"] != transfer.sender_user_id:
                cursor.execute("ROLLBACK;")
                raise HTTPException(
                    status_code=403,
                    detail=f"⛔ Клиент '{actor['username']}' (ID #{actor['id']}) может переводить средства только со своего счёта.",
                )
            client_ip = request.client.host if request.client else "127.0.0.1"
            origin = {"ip": client_ip, "geo": "Astana, KZ (Verified Local Subnet)", "risk": "LOW"}

        if transfer.idempotency_key:
            cursor.execute("SELECT * FROM transactions WHERE idempotency_key = ?", (transfer.idempotency_key,))
            existing_tx = cursor.fetchone()
            if existing_tx:
                cursor.execute("SELECT encrypted_balance FROM accounts WHERE id = ?", (existing_tx["sender_account_id"],))
                acc_row = cursor.fetchone()
                current_bal = float(decrypt_data(acc_row["encrypted_balance"])) if acc_row else 0.0
                cursor.execute("COMMIT;")
                return {
                    "status": "IDEMPOTENT_REPLAY",
                    "message": "Повторный запрос с тем же ключом: списание не дублировалось.",
                    "tx_id": existing_tx["id"],
                    "transferred_amount": existing_tx["amount"],
                    "sender_new_balance": current_bal,
                    "risk_score": existing_tx["risk_score"],
                    "origin": origin,
                }

        cursor.execute("SELECT id FROM blocked_ips WHERE ip_address = ?", (origin["ip"],))
        if cursor.fetchone():
            cursor.execute("ROLLBACK;")
            raise HTTPException(
                status_code=403,
                detail=f"🚨 Доступ с IP {origin['ip']} заблокирован по решению DB Blacklist Guard.",
            )

        if transfer.amount <= 0:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="Сумма должна быть больше нуля (ограничение CHECK в БД)")
        if transfer.sender_user_id == transfer.receiver_user_id:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="Нельзя переводить средства самому себе")

        cursor.execute("SELECT id, encrypted_balance, daily_limit FROM accounts WHERE user_id = ?", (transfer.sender_user_id,))
        sender_acc = cursor.fetchone()
        cursor.execute("SELECT id, encrypted_balance FROM accounts WHERE user_id = ?", (transfer.receiver_user_id,))
        receiver_acc = cursor.fetchone()

        if not sender_acc or not receiver_acc:
            cursor.execute("ROLLBACK;")
            raise HTTPException(status_code=404, detail="Счет отправителя или получателя не найден")

        sender_balance = float(decrypt_data(sender_acc["encrypted_balance"]))

        cursor.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS spent_today
            FROM transactions
            WHERE sender_account_id = ? AND status = 'SUCCESS' AND date(created_at) = date('now')
            """,
            (sender_acc["id"],),
        )
        spent_today = float(cursor.fetchone()["spent_today"])
        if not transfer.is_red_team and (spent_today + transfer.amount > sender_acc["daily_limit"]):
            write_audit_log(
                cursor,
                actor["id"],
                "DAILY_LIMIT_EXCEEDED",
                f"[{actor['username']}] Превышен дневной лимит ({spent_today + transfer.amount:,.0f} > {sender_acc['daily_limit']:,.0f} KZT).",
            )
            cursor.execute("COMMIT;")
            raise HTTPException(
                status_code=403,
                detail=f"⛔ Превышен дневной лимит счёта ({sender_acc['daily_limit']:,.0f} KZT). Уже израсходовано: {spent_today:,.0f} KZT.",
            )

        if transfer.amount > 100000 and not transfer.is_red_team:
            if not transfer.otp_code:
                code = issue_otp_in_db(cursor, transfer.sender_user_id)
                cursor.execute("COMMIT;")
                raise HTTPException(
                    status_code=401,
                    detail={"status": "2FA_REQUIRED", "message": "Требуется 2FA", "demo_otp_push": code},
                )
            elif not verify_and_consume_otp(cursor, transfer.sender_user_id, transfer.otp_code):
                write_audit_log(
                    cursor,
                    actor["id"],
                    "INVALID_2FA_CODE",
                    f"[{actor['username']}] Неверный или просроченный код 2FA при переводе {transfer.amount:,.0f} KZT.",
                )
                cursor.execute("COMMIT;")
                raise HTTPException(
                    status_code=403,
                    detail={
                        "status": "BLOCKED",
                        "reason": "Invalid or Expired 2FA",
                        "risk_score": 95,
                        "details": ["Invalid or Expired 2FA Code"],
                        "origin": origin,
                    },
                )

        risk_score = 0
        fraud_reasons = []

        if sender_balance < transfer.amount:
            risk_score += 100
            fraud_reasons.append("Insufficient funds")
        if transfer.amount > 500000:
            risk_score += 50
            fraud_reasons.append("High-value anomaly (>500k KZT)")
        if transfer.is_red_team:
            risk_score += 45
            fraud_reasons.append(f"Suspicious ASN ({origin['geo']})")

        cursor.execute(
            """
            SELECT COUNT(*) as cnt FROM transactions
            WHERE sender_account_id = ? AND created_at >= datetime('now', '-1 minute')
            """,
            (sender_acc["id"],),
        )
        if cursor.fetchone()["cnt"] >= 3:
            risk_score += 85
            fraud_reasons.append("Velocity threshold breached")

        clamped_risk = min(risk_score, 100)

        if risk_score >= 80 or sender_balance < transfer.amount:
            cursor.execute(
                """
                INSERT INTO transactions (idempotency_key, sender_account_id, receiver_account_id, amount, status, risk_score)
                VALUES (?, ?, ?, ?, 'BLOCKED', ?)
                """,
                (transfer.idempotency_key, sender_acc["id"], receiver_acc["id"], transfer.amount, clamped_risk),
            )

            cursor.execute(
                "INSERT OR IGNORE INTO blocked_ips (ip_address, geo_info, reason) VALUES (?, ?, ?)",
                (origin["ip"], origin["geo"], f"Fraud blocked with risk score {risk_score}"),
            )

            create_incident(
                cursor,
                "FRAUD_ATTEMPT_BLOCKED",
                "HIGH" if risk_score < 95 else "CRITICAL",
                f"Отражена подозрительная операция на {transfer.amount:,.0f} KZT (Risk: {risk_score}, причины: {', '.join(fraud_reasons)})",
                origin["ip"],
            )

            write_audit_log(
                cursor,
                actor["id"],
                "FRAUD_BLOCKED",
                f"[IP: {origin['ip']} | {actor['username']}] Блокировка перевода на {transfer.amount} KZT (Risk: {risk_score})",
            )
            cursor.execute("COMMIT;")
            raise HTTPException(
                status_code=403,
                detail={
                    "status": "BLOCKED",
                    "reason": "Anti-Fraud Triggered",
                    "risk_score": risk_score,
                    "details": fraud_reasons,
                    "origin": origin,
                },
            )

        receiver_balance = float(decrypt_data(receiver_acc["encrypted_balance"]))
        new_sender_balance = sender_balance - transfer.amount
        new_receiver_balance = receiver_balance + transfer.amount

        cursor.execute(
            "UPDATE accounts SET encrypted_balance = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (encrypt_data(str(new_sender_balance)), sender_acc["id"]),
        )
        cursor.execute(
            "UPDATE accounts SET encrypted_balance = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (encrypt_data(str(new_receiver_balance)), receiver_acc["id"]),
        )

        cursor.execute(
            """
            INSERT INTO transactions (idempotency_key, sender_account_id, receiver_account_id, amount, status, risk_score)
            VALUES (?, ?, ?, ?, 'SUCCESS', ?)
            """,
            (transfer.idempotency_key, sender_acc["id"], receiver_acc["id"], transfer.amount, clamped_risk),
        )
        write_audit_log(
            cursor,
            actor["id"],
            "TRANSFER_SUCCESS",
            f"[{actor['username']} | {actor['role']}] Перевод {transfer.amount} KZT (#{transfer.sender_user_id} -> #{transfer.receiver_user_id}, key={transfer.idempotency_key or 'none'}).",
        )

        cursor.execute("COMMIT;")
        return {
            "status": "SUCCESS",
            "transferred_amount": transfer.amount,
            "sender_new_balance": new_sender_balance,
            "risk_score": risk_score,
            "origin": origin,
        }

    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    except Exception as e:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/incidents", summary="Журнал инцидентов безопасности (только персонал/аудит)")
def get_incidents(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        return {"status": "success", "incidents": [dict(r) for r in rows]}
    finally:
        cursor.close()
        conn.close()


@app.post("/incidents/{incident_id}/resolve", summary="Закрыть инцидент после разбора (только SECURITY_OFFICER)")
def resolve_incident(incident_id: int, authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN IMMEDIATE;")
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("SECURITY_OFFICER",))
        cursor.execute(
            "UPDATE incidents SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
            (incident_id,),
        )
        write_audit_log(
            cursor,
            actor["id"],
            "INCIDENT_RESOLVED",
            f"[{actor['username']} | {actor['role']}] Инцидент #{incident_id} закрыт после разбора.",
        )
        cursor.execute("COMMIT;")
        return {"status": "SUCCESS", "incident_id": incident_id}
    except HTTPException as he:
        if conn.in_transaction:
            cursor.execute("ROLLBACK;")
        raise he
    finally:
        cursor.close()
        conn.close()


@app.get("/audit-logs", summary="Журнал аудита (только персонал/аудит)")
def get_audit_logs(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 35")
        logs = cursor.fetchall()
        return {"status": "success", "logs": [dict(log) for log in logs]}
    finally:
        cursor.close()
        conn.close()


@app.get("/blocked-ips", summary="Список заблокированных в БД IP (только персонал/аудит)")
def get_blocked_ips(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
        ips = cursor.fetchall()
        return {"status": "success", "blocked_ips": [dict(ip) for ip in ips]}
    finally:
        cursor.close()
        conn.close()


@app.get("/stats", summary="SOC метрики (только персонал/аудит)")
def get_security_stats(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT COUNT(*) as total FROM transactions WHERE status = 'SUCCESS'")
        success_count = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) as total FROM transactions WHERE status = 'BLOCKED'")
        blocked_count = cursor.fetchone()["total"]
        cursor.execute("SELECT SUM(amount) as total_sum FROM transactions WHERE status = 'SUCCESS'")
        total_volume = cursor.fetchone()["total_sum"] or 0.0
        cursor.execute("SELECT MAX(risk_score) as max_r FROM transactions")
        max_r = cursor.fetchone()["max_r"] or 0
        cursor.execute("SELECT COUNT(*) as cnt FROM blocked_ips")
        db_blacklisted_count = cursor.fetchone()["cnt"]
        cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'OPEN'")
        open_incidents_count = cursor.fetchone()["cnt"]

        return {
            "successful_transactions": success_count,
            "blocked_fraud_attempts": blocked_count,
            "total_protected_volume_kzt": total_volume,
            "peak_risk_score": max_r,
            "db_blacklisted_ips": db_blacklisted_count,
            "open_incidents": open_incidents_count,
        }
    finally:
        cursor.close()
        conn.close()


@app.get("/export-report", summary="Выгрузка комплаенс-отчёта (только персонал/аудит)")
def export_compliance_report(authorization: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        actor = require_authenticated_user(cursor, authorization, allowed_roles=("OPERATOR", "SECURITY_OFFICER", "AUDITOR"))
        cursor.execute("SELECT * FROM transactions ORDER BY id DESC")
        txs = [dict(row) for row in cursor.fetchall()]
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
        logs = [dict(row) for row in cursor.fetchall()]
        cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
        bips = [dict(row) for row in cursor.fetchall()]
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
        incs = [dict(row) for row in cursor.fetchall()]

        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        payload_str = json.dumps(
            {"txs": txs, "logs": logs, "blocked_ips": bips, "incidents": incs},
            sort_keys=True,
            ensure_ascii=False,
        )
        sha256_seal = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

        return {
            "document_title": "SECUREFIN CORE — ENTERPRISE COMPLIANCE REPORT",
            "exported_by": f"{actor['username']} ({actor['role']})",
            "generated_at": generated_at,
            "cryptographic_seal_sha256": sha256_seal,
            "encryption_standard": "AES-128-CBC + Session RBAC + Atomic Locks + DB-Persisted 2FA/Lockdown + Hash-Chained Audit",
            "total_transactions": len(txs),
            "total_audit_records": len(logs),
            "db_blocked_ips": len(bips),
            "total_incidents": len(incs),
            "transactions": txs,
            "audit_logs": logs,
            "blocked_ips": bips,
            "incidents": incs,
        }
    finally:
        cursor.close()
        conn.close()