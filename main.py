from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import hashlib
import random
import json
from datetime import datetime

from database import get_db_connection, init_db
from security import hash_password, encrypt_data, decrypt_data

app = FastAPI(title="SecureFin Core Enterprise", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ACTIVE_OTPS = {}
SYSTEM_LOCKDOWN = False

THREAT_ORIGINS = [
    {"ip": "185.220.101.42", "geo": "Amsterdam, NL (Tor Exit Node)", "risk": "CRITICAL"},
    {"ip": "45.155.205.89", "geo": "Frankfurt, DE (Anonymous VPN)", "risk": "HIGH"},
    {"ip": "91.240.118.17", "geo": "Bucharest, RO (Botnet Proxy)", "risk": "CRITICAL"},
    {"ip": "103.253.41.98", "geo": "Singapore, SG (Cloud Datacenter)", "risk": "HIGH"},
    {"ip": "194.26.135.21", "geo": "Riga, LV (Suspicious ASN)", "risk": "HIGH"},
]


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


@app.on_event("startup")
def startup_event():
    init_db()


class UserRegister(BaseModel):
    username: str
    password: str
    initial_balance: float = 100000.0
    daily_limit: float = 300000.0
    role: str = "CLIENT"


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
    cursor.execute("SELECT COUNT(*) as cnt FROM blocked_ips")
    blocked_ips_count = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'OPEN'")
    open_incidents = cursor.fetchone()["cnt"]
    cursor.close()
    conn.close()

    return {
        "project": "SecureFin Core Enterprise",
        "status": "ARMED & OPERATIONAL",
        "system_lockdown": SYSTEM_LOCKDOWN,
        "open_incidents": open_incidents,
        "persisted_blocked_ips_in_db": blocked_ips_count,
    }


@app.get("/db-chain-check", summary="Проверка целостности хеш-цепочки и срез VIEW")
def check_db_chain():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        logs = [dict(row) for row in cursor.fetchall()]

        chain_valid = True
        broken_at_id = None
        expected_prev = "GENESIS_BLOCK"

        for row in logs:
            if row["action"].startswith("DB_TRIGGER_"):
                continue
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

        return {
            "chain_valid": chain_valid,
            "broken_at_id": broken_at_id,
            "total_audit_rows": len(logs),
            "recent_view_transactions": view_rows,
        }
    finally:
        cursor.close()
        conn.close()


@app.post("/emergency-lockdown", summary="Переключение режима изоляции (только SECURITY_OFFICER)")
def emergency_lockdown(x_role: Optional[str] = Header(default="SECURITY_OFFICER")):
    if x_role != "SECURITY_OFFICER":
        raise HTTPException(
            status_code=403,
            detail=f"⛔ Доступ запрещён для роли '{x_role}'. Управление Kill Switch разрешено только SECURITY_OFFICER.",
        )

    global SYSTEM_LOCKDOWN
    SYSTEM_LOCKDOWN = not SYSTEM_LOCKDOWN

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if SYSTEM_LOCKDOWN:
            write_audit_log(
                cursor,
                1,
                "DEFCON_1_LOCKDOWN",
                f"[{x_role}] Активирован аварийный Kill Switch. Шлюзы заблокированы на бэкенде.",
            )
            create_incident(
                cursor,
                "EMERGENCY_LOCKDOWN",
                "CRITICAL",
                "Контур переведён в режим изоляции DEFCON 1 офицером безопасности.",
                "LOCAL_CONSOLE",
            )
        else:
            write_audit_log(
                cursor,
                1,
                "DEFCON_RESTORED",
                f"[{x_role}] Аварийный режим отключен. Штатная работа восстановлена.",
            )
            cursor.execute(
                """
                UPDATE incidents
                SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP
                WHERE incident_type = 'EMERGENCY_LOCKDOWN' AND status = 'OPEN'
                """
            )
        conn.commit()
        return {"status": "SUCCESS", "system_lockdown": SYSTEM_LOCKDOWN, "message": "Статус изоляции изменен."}
    finally:
        cursor.close()
        conn.close()


@app.post("/update-limit", summary="Изменение дневного лимита счёта (OPERATOR / SECURITY_OFFICER)")
def update_account_limit(req: LimitUpdateRequest, x_role: Optional[str] = Header(default="OPERATOR")):
    if x_role not in ("OPERATOR", "SECURITY_OFFICER"):
        raise HTTPException(
            status_code=403,
            detail=f"⛔ Роль '{x_role}' не имеет прав на изменение дневного лимита.",
        )
    if req.daily_limit <= 0:
        raise HTTPException(status_code=400, detail="Дневной лимит должен быть больше нуля")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM accounts WHERE user_id = ?", (req.user_id,))
        acc = cursor.fetchone()
        if not acc:
            raise HTTPException(status_code=404, detail="Счёт пользователя не найден")

        cursor.execute("UPDATE accounts SET daily_limit = ? WHERE user_id = ?", (req.daily_limit, req.user_id))
        write_audit_log(
            cursor,
            req.user_id,
            "DAILY_LIMIT_UPDATED",
            f"[{x_role}] Установлен новый дневной лимит: {req.daily_limit:,.0f} KZT.",
        )
        conn.commit()
        return {"status": "SUCCESS", "user_id": req.user_id, "daily_limit": req.daily_limit}
    finally:
        cursor.close()
        conn.close()


@app.post("/register")
def register(user: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Пользователь с таким именем уже существует")

        safe_role = user.role if user.role in ("CLIENT", "OPERATOR", "SECURITY_OFFICER", "AUDITOR") else "CLIENT"
        pwd_hash = hash_password(user.password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (user.username, pwd_hash, safe_role),
        )
        user_id = cursor.lastrowid

        encrypted_bal = encrypt_data(str(user.initial_balance))
        cursor.execute(
            "INSERT INTO accounts (user_id, encrypted_balance, daily_limit) VALUES (?, ?, ?)",
            (user_id, encrypted_bal, user.daily_limit),
        )

        write_audit_log(
            cursor,
            user_id,
            "USER_REGISTERED",
            f"Создан защищённый счёт (роль: {safe_role}, лимит: {user.daily_limit:,.0f} KZT/день).",
        )
        conn.commit()
        return {"status": "success", "user_id": user_id, "username": user.username, "role": safe_role}
    except HTTPException as he:
        raise he
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/account/{user_id}", summary="Получить баланс и дневной лимит")
def get_account_balance(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
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
def request_otp(req: OTPRequest):
    code = str(random.randint(100000, 999999))
    ACTIVE_OTPS[req.user_id] = code
    return {"status": "OTP_SENT", "otp_code": code}


@app.post("/transfer", summary="Перевод средств с идемпотентностью, дневным лимитом, Anti-Fraud и 2FA")
def transfer_funds(transfer: TransferRequest, request: Request):
    global SYSTEM_LOCKDOWN
    if SYSTEM_LOCKDOWN:
        raise HTTPException(
            status_code=403,
            detail="🚨 СИСТЕМА В РЕЖИМЕ ИЗОЛЯЦИИ (DEFCON 1). Транзакции заблокированы.",
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    if transfer.is_red_team:
        origin = random.choice(THREAT_ORIGINS)
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"
        origin = {"ip": client_ip, "geo": "Astana, KZ (Verified Local Subnet)", "risk": "LOW"}

    try:
        # 1. Проверка идемпотентности (защита от повторного списания по тому же ключу)
        if transfer.idempotency_key:
            cursor.execute("SELECT * FROM transactions WHERE idempotency_key = ?", (transfer.idempotency_key,))
            existing_tx = cursor.fetchone()
            if existing_tx:
                cursor.execute("SELECT encrypted_balance FROM accounts WHERE id = ?", (existing_tx["sender_account_id"],))
                acc_row = cursor.fetchone()
                current_bal = float(decrypt_data(acc_row["encrypted_balance"])) if acc_row else 0.0
                return {
                    "status": "IDEMPOTENT_REPLAY",
                    "message": "Повторный запрос с тем же ключом: списание не дублировалось.",
                    "tx_id": existing_tx["id"],
                    "transferred_amount": existing_tx["amount"],
                    "sender_new_balance": current_bal,
                    "risk_score": existing_tx["risk_score"],
                    "origin": origin,
                }

        # 2. Проверка IP в персистентном блеклисте БД
        cursor.execute("SELECT id FROM blocked_ips WHERE ip_address = ?", (origin["ip"],))
        if cursor.fetchone():
            raise HTTPException(
                status_code=403,
                detail=f"🚨 Доступ с IP {origin['ip']} заблокирован по решению DB Blacklist Guard.",
            )

        if transfer.amount <= 0:
            raise HTTPException(status_code=400, detail="Сумма должна быть больше нуля (ограничение CHECK в БД)")
        if transfer.sender_user_id == transfer.receiver_user_id:
            raise HTTPException(status_code=400, detail="Нельзя переводить средства самому себе")

        cursor.execute("SELECT id, encrypted_balance, daily_limit FROM accounts WHERE user_id = ?", (transfer.sender_user_id,))
        sender_acc = cursor.fetchone()
        cursor.execute("SELECT id, encrypted_balance FROM accounts WHERE user_id = ?", (transfer.receiver_user_id,))
        receiver_acc = cursor.fetchone()

        if not sender_acc or not receiver_acc:
            raise HTTPException(status_code=404, detail="Счет отправителя или получателя не найден")

        sender_balance = float(decrypt_data(sender_acc["encrypted_balance"]))

        # 3. Проверка дневного лимита счёта
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
                transfer.sender_user_id,
                "DAILY_LIMIT_EXCEEDED",
                f"Превышен дневной лимит ({spent_today + transfer.amount:,.0f} > {sender_acc['daily_limit']:,.0f} KZT).",
            )
            conn.commit()
            raise HTTPException(
                status_code=403,
                detail=f"⛔ Превышен дневной лимит счёта ({sender_acc['daily_limit']:,.0f} KZT). Уже израсходовано: {spent_today:,.0f} KZT.",
            )

        # 4. 2FA проверка при сумме > 100 000 KZT
        if transfer.amount > 100000 and not transfer.is_red_team:
            expected_otp = ACTIVE_OTPS.get(transfer.sender_user_id)
            if not transfer.otp_code:
                code = str(random.randint(100000, 999999))
                ACTIVE_OTPS[transfer.sender_user_id] = code
                raise HTTPException(
                    status_code=401,
                    detail={"status": "2FA_REQUIRED", "message": "Требуется 2FA", "demo_otp_push": code},
                )
            elif transfer.otp_code != expected_otp:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "status": "BLOCKED",
                        "reason": "Invalid 2FA",
                        "risk_score": 95,
                        "details": ["Invalid 2FA Code"],
                        "origin": origin,
                    },
                )
            else:
                ACTIVE_OTPS.pop(transfer.sender_user_id, None)

        # 5. Anti-Fraud движок
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
                transfer.sender_user_id,
                "FRAUD_BLOCKED",
                f"[IP: {origin['ip']}] Блокировка перевода на {transfer.amount} KZT (Risk: {risk_score})",
            )
            conn.commit()
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
            transfer.sender_user_id,
            "TRANSFER_SUCCESS",
            f"[IP: {origin['ip']}] Перевод {transfer.amount} KZT успешен (key={transfer.idempotency_key or 'none'}).",
        )

        conn.commit()
        return {
            "status": "SUCCESS",
            "transferred_amount": transfer.amount,
            "sender_new_balance": new_sender_balance,
            "risk_score": risk_score,
            "origin": origin,
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/incidents", summary="Журнал инцидентов безопасности")
def get_incidents():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        return {"status": "success", "incidents": [dict(r) for r in rows]}
    finally:
        cursor.close()
        conn.close()


@app.post("/incidents/{incident_id}/resolve", summary="Закрыть инцидент после разбора")
def resolve_incident(incident_id: int, x_role: Optional[str] = Header(default="SECURITY_OFFICER")):
    if x_role != "SECURITY_OFFICER":
        raise HTTPException(status_code=403, detail="Закрывать инциденты может только SECURITY_OFFICER.")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE incidents SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
            (incident_id,),
        )
        write_audit_log(cursor, 1, "INCIDENT_RESOLVED", f"[{x_role}] Инцидент #{incident_id} закрыт после разбора.")
        conn.commit()
        return {"status": "SUCCESS", "incident_id": incident_id}
    finally:
        cursor.close()
        conn.close()


@app.get("/audit-logs")
def get_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 35")
        logs = cursor.fetchall()
        return {"status": "success", "logs": [dict(log) for log in logs]}
    finally:
        cursor.close()
        conn.close()


@app.get("/blocked-ips", summary="Получить список заблокированных в БД IP")
def get_blocked_ips():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
        ips = cursor.fetchall()
        return {"status": "success", "blocked_ips": [dict(ip) for ip in ips]}
    finally:
        cursor.close()
        conn.close()


@app.get("/stats")
def get_security_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
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


@app.get("/export-report")
def export_compliance_report():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
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
            "generated_at": generated_at,
            "cryptographic_seal_sha256": sha256_seal,
            "encryption_standard": "AES-128-CBC + RBAC + Idempotency + Daily Limits + Incident Ledger",
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