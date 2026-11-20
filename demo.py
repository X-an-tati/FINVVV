import random
import requests

BASE_URL = "http://127.0.0.1:8000"


def run_demo():
    print("=" * 60)
    print("🚀 ДЕМО-СЦЕНАРИЙ SECUREFIN CORE ENTERPRISE (v7.0)")
    print("=" * 60)

    r_root = requests.get(f"{BASE_URL}/", timeout=5)
    print("\n[0] Статус сервера:", r_root.status_code, r_root.json())

    # 1. Вход под операционистом и аудитором
    r_op = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "bank_operator", "password": "op123"},
        timeout=5,
    )
    assert r_op.status_code == 200, f"Ошибка входа оператора: {r_op.text}"
    op_headers = {"Authorization": f"Bearer {r_op.json()['token']}"}

    r_aud = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "chief_auditor", "password": "aud123"},
        timeout=5,
    )
    assert r_aud.status_code == 200, f"Ошибка входа аудитора: {r_aud.text}"
    aud_headers = {"Authorization": f"Bearer {r_aud.json()['token']}"}

    # 2. Заявка клиента -> одобрение операционистом -> вход клиента
    suffix = random.randint(1000, 9999)
    client_user = f"client_{suffix}"
    client_pwd = "pass1234"

    r_app = requests.post(
        f"{BASE_URL}/applications",
        json={
            "username": client_user,
            "password": client_pwd,
            "requested_balance": 200000.0,
            "requested_limit": 150000.0,
        },
        timeout=5,
    )
    assert r_app.status_code == 200, f"Ошибка подачи заявки: {r_app.text}"
    app_id = r_app.json()["application_id"]
    print(f"\n[1] Создана заявка #{app_id} для '{client_user}' (статус PENDING)")

    r_approve = requests.post(
        f"{BASE_URL}/applications/{app_id}/approve",
        headers=op_headers,
        timeout=5,
    )
    assert r_approve.status_code == 200, f"Ошибка одобрения заявки: {r_approve.text}"
    client_id = r_approve.json()["client_user_id"]
    print(f"[2] Заявка одобрена операционистом. Открыт счёт CLIENT ID #{client_id}")

    r_cli_login = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": client_user, "password": client_pwd},
        timeout=5,
    )
    assert r_cli_login.status_code == 200, f"Ошибка входа клиента: {r_cli_login.text}"
    cli_headers = {"Authorization": f"Bearer {r_cli_login.json()['token']}"}

    # 3. Баланс клиента + перевод с ключом идемпотентности
    bal = requests.get(f"{BASE_URL}/account/{client_id}", headers=cli_headers, timeout=5).json()
    print(f"[3] Баланс клиента: {bal.get('balance')} {bal.get('currency')}")

    idem_key = f"demo_idem_{suffix}"
    tx1 = requests.post(
        f"{BASE_URL}/transfer",
        headers=cli_headers,
        json={
            "sender_user_id": client_id,
            "receiver_user_id": 2,
            "amount": 10000.0,
            "idempotency_key": idem_key,
        },
        timeout=5,
    ).json()
    tx2 = requests.post(
        f"{BASE_URL}/transfer",
        headers=cli_headers,
        json={
            "sender_user_id": client_id,
            "receiver_user_id": 2,
            "amount": 10000.0,
            "idempotency_key": idem_key,
        },
        timeout=5,
    ).json()
    print(f"[4] Первый перевод: {tx1.get('status')} | Повтор с тем же ключом: {tx2.get('status')}")

    # 4. Проверка хеш-цепочки аудита
    chain = requests.get(f"{BASE_URL}/db-chain-check", headers=aud_headers, timeout=5).json()
    print(
        f"[5] Целостность хеш-цепочки: {chain.get('chain_valid')} "
        f"(записей в аудите: {chain.get('total_audit_rows')})"
    )
    print("=" * 60)
    print("✨ ДЕМО УСПЕШНО ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()