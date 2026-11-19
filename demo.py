import requests
import time
import random

BASE_URL = "http://127.0.0.1:8000"

def run_demo():
    print("=" * 60)
    print("🚀 ЗАПУСК ДЕМОНСТРАЦИИ SYSTEM SECUREFIN CORE")
    print("=" * 60)

    rand_suffix = random.randint(1000, 9999)
    alice_name = f"alice_{rand_suffix}"
    bob_name = f"bob_{rand_suffix}"

    # 1. Регистрация пользователей
    print(f"\n[1] Регистрируем пользователей ({alice_name} и {bob_name})...")
    
    alice_data = {"username": alice_name, "password": "securepassword123", "initial_balance": 100000.0}
    bob_data = {"username": bob_name, "password": "securepassword123", "initial_balance": 50000.0}

    res_alice = requests.post(f"{BASE_URL}/register", json=alice_data)
    res_bob = requests.post(f"{BASE_URL}/register", json=bob_data)

    print(f" Ответ регистрации Алисы: {res_alice.status_code} -> {res_alice.json()}")
    print(f" Ответ регистрации Боба: {res_bob.status_code} -> {res_bob.json()}")

    if res_alice.status_code != 200 or res_bob.status_code != 200:
        print("[-] Ошибка регистрации! Проверь бэкенд.")
        return

    alice_id = res_alice.json().get("user_id")
    bob_id = res_bob.json().get("user_id")

    print(f" [+] Успешно! ID Алисы: {alice_id}, ID Боба: {bob_id}")

    # 2. Проверка балансов
    print(f"\n[2] Проверяем зашифрованные балансы через API для ID {alice_id}...")
    bal_res = requests.get(f"{BASE_URL}/account/{alice_id}")
    bal_alice = bal_res.json()
    print(f" [+] Баланс Алисы (расшифрован на лету): {bal_alice.get('balance')} {bal_alice.get('currency')} (Статус: {bal_alice.get('security_status')})")

    # 3. Легитимный перевод
    print(f"\n[3] Совершаем легитимный перевод (5,000 тенге) от ID {alice_id} к ID {bob_id}...")
    transfer_payload = {
        "sender_user_id": alice_id,
        "receiver_user_id": bob_id,
        "amount": 5000.0
    }
    res_tx = requests.post(f"{BASE_URL}/transfer", json=transfer_payload)
    print(f" Ответ сервера: {res_tx.status_code} -> {res_tx.json()}")

    # 4. Стресс-тест / Антифрод (Velocity Check)
    print("\n[4] ⚡ СТРЕСС-ТЕСТ: Пытаемся заспамить переводами для вызова Anti-Fraud...")
    for i in range(4):
        print(f"   Попытка перевода #{i+1}...")
        res_spam = requests.post(f"{BASE_URL}/transfer", json=transfer_payload)
        print(f"   Статус: {res_spam.status_code} | Ответ: {res_spam.json()}")
        time.sleep(0.2)

    # 5. Выгрузка логов безопасности
    print("\n[5] 🛡️ Выгружаем неизменяемый Аудит Безопасности (Audit Logs):")
    logs_res = requests.get(f"{BASE_URL}/audit-logs").json()
    for log in logs_res.get("logs", [])[:5]:
        print(f"   🔹 [{log['created_at']}] Юзер ID {log['user_id']} | Событие: {log['action']} | Детали: {log['details']}")

    print("\n" + "=" * 60)
    print("✨ ДЕМО УСПЕШНО ЗАВЕРШЕНО. ЖЮРИ В ВОСТОРГЕ!")
    print("=" * 60)

if __name__ == "__main__":
    run_demo()