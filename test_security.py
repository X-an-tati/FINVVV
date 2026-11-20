import os
import database

database.DB_NAME = "test_securefin.db"
if os.path.exists("test_securefin.db"):
    os.remove("test_securefin.db")

from fastapi.testclient import TestClient
from main import app


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def run_all_tests():
    with TestClient(app) as client:
        # 1. Вход под штатными ролями из сида БД
        r_op = client.post("/auth/login", json={"username": "bank_operator", "password": "op123"})
        assert r_op.status_code == 200, r_op.text
        op_token = r_op.json()["token"]

        r_soc = client.post("/auth/login", json={"username": "soc_officer", "password": "soc123"})
        assert r_soc.status_code == 200, r_soc.text
        soc_token = r_soc.json()["token"]

        r_aud = client.post("/auth/login", json={"username": "chief_auditor", "password": "aud123"})
        assert r_aud.status_code == 200, r_aud.text
        aud_token = r_aud.json()["token"]

        # 2. Заявка клиента -> вход до одобрения запрещён -> одобрение операционистом -> вход разрешён
        r_app = client.post(
            "/applications",
            json={
                "username": "alice_test",
                "password": "secret123",
                "requested_balance": 400000,
                "requested_limit": 250000,
            },
        )
        assert r_app.status_code == 200, r_app.text
        app_id = r_app.json()["application_id"]

        r_early_login = client.post("/auth/login", json={"username": "alice_test", "password": "secret123"})
        assert r_early_login.status_code == 403

        # Аудитор не может одобрять заявки
        r_aud_approve = client.post(f"/applications/{app_id}/approve", headers=auth_header(aud_token))
        assert r_aud_approve.status_code == 403

        # Операционист одобряет заявку
        r_approve = client.post(f"/applications/{app_id}/approve", headers=auth_header(op_token))
        assert r_approve.status_code == 200, r_approve.text
        alice_id = r_approve.json()["client_user_id"]

        r_alice_login = client.post("/auth/login", json={"username": "alice_test", "password": "secret123"})
        assert r_alice_login.status_code == 200, r_alice_login.text
        alice_token = r_alice_login.json()["token"]

        # 3. Изоляция клиента: свой счёт видит, чужой — 403, аудит-логи — 403
        assert client.get(f"/account/{alice_id}", headers=auth_header(alice_token)).status_code == 200
        assert client.get("/account/1", headers=auth_header(alice_token)).status_code == 403
        assert client.get("/audit-logs", headers=auth_header(alice_token)).status_code == 403

        # 4. Идемпотентность перевода (повтор с тем же ключом не списывает дважды)
        idem = "idem_key_test_001"
        tx1 = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={"sender_user_id": alice_id, "receiver_user_id": 2, "amount": 50000, "idempotency_key": idem},
        )
        assert tx1.status_code == 200 and tx1.json()["sender_new_balance"] == 350000.0

        tx2 = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={"sender_user_id": alice_id, "receiver_user_id": 2, "amount": 50000, "idempotency_key": idem},
        )
        assert tx2.status_code == 200 and tx2.json()["status"] == "IDEMPOTENT_REPLAY"
        assert tx2.json()["sender_new_balance"] == 350000.0

        # 5. 2FA на сумму > 100 000 KZT (код хранится в БД)
        tx_2fa = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={"sender_user_id": alice_id, "receiver_user_id": 2, "amount": 150000, "idempotency_key": "idem_2fa_1"},
        )
        assert tx_2fa.status_code == 401
        otp = tx_2fa.json()["detail"]["demo_otp_push"]

        tx_2fa_ok = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={
                "sender_user_id": alice_id,
                "receiver_user_id": 2,
                "amount": 150000,
                "otp_code": otp,
                "idempotency_key": "idem_2fa_1",
            },
        )
        assert tx_2fa_ok.status_code == 200 and tx_2fa_ok.json()["sender_new_balance"] == 200000.0

        # 6. Дневной лимит (осталось 50 000 из 250 000 -> попытка перевести 60 000 блокируется)
        tx_limit = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={"sender_user_id": alice_id, "receiver_user_id": 2, "amount": 60000, "idempotency_key": "idem_lim"},
        )
        assert tx_limit.status_code == 403

        # 7. Kill Switch (только SECURITY_OFFICER, состояние сохраняется в БД)
        assert client.post("/emergency-lockdown", headers=auth_header(op_token)).status_code == 403
        ks_on = client.post("/emergency-lockdown", headers=auth_header(soc_token))
        assert ks_on.status_code == 200 and ks_on.json()["system_lockdown"] is True

        tx_locked = client.post(
            "/transfer",
            headers=auth_header(alice_token),
            json={"sender_user_id": alice_id, "receiver_user_id": 2, "amount": 1000, "idempotency_key": "idem_ks"},
        )
        assert tx_locked.status_code == 403

        client.post("/emergency-lockdown", headers=auth_header(soc_token))

        # 8. Проверка целостности SHA-256 хеш-цепочки аудита (100% записей без пропусков)
        chain = client.get("/db-chain-check", headers=auth_header(aud_token))
        assert chain.status_code == 200
        assert chain.json()["chain_valid"] is True
        assert chain.json()["db_trigger_events_count"] > 0

    if os.path.exists("test_securefin.db"):
        os.remove("test_securefin.db")
    for suffix in ("-wal", "-shm"):
        if os.path.exists("test_securefin.db" + suffix):
            os.remove("test_securefin.db" + suffix)

    print("✅ ВСЕ 8 ИНТЕГРАЦИОННЫХ ТЕСТОВ БЕЗОПАСНОСТИ И БИЗНЕС-ЛОГИКИ ПРОЙДЕНЫ!")


if __name__ == "__main__":
    run_all_tests()