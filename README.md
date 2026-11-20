# SecureFin Core Enterprise (v7.0-FINAL)

Автономное банковское ядро и центр мониторинга информационной безопасности (SOC) на базе **FastAPI**, **SQLite (WAL + Triggers)**, **Cryptography (`Fernet` / `SHA-256`)** и **Tailwind CSS**.

Проект моделирует защищённый банковский контур с разграничением ролей, закрытым процессом открытия клиентских счетов через заявки, шифрованием остатков в базе данных, атомарными переводами под блокировкой транзакций, антифрод-скорингом, двухфакторной проверкой (`2FA`), аварийным режимом изоляции (`DEFCON 1`) и криптографической хеш-цепочкой аудита.

---

## Содержание

1. [Архитектура и модель угроз](#1-архитектура-и-модель-угроз)
2. [Быстрый старт и запуск](#2-быстрый-старт-и-запуск)
3. [Роли, учётные записи и матрица доступа (RBAC)](#3-роли-учётные-записи-и-матрица-доступа-rbac)
4. [Схема базы данных, ограничения, триггеры и VIEW](#4-схема-базы-данных-ограничения-триггеры-и-view)
5. [Криптография, 2FA и защита от гонки запросов](#5-криптография-2fa-и-защита-от-гонки-запросов)
6. [Жизненный цикл перевода и Anti-Fraud скоринг](#6-жизненный-цикл-перевода-и-anti-fraud-скоринг)
7. [Справочник HTTP-эндпоинтов API](#7-справочник-http-эндпоинтов-api)
8. [Режимы работы веб-интерфейса (`index.html`)](#8-режимы-работы-веб-интерфейса-indexhtml)
9. [Автоматическое тестирование и разбор инцидентов](#9-автоматическое-тестирование-и-разбор-инцидентов)
10. [Ограничения MVP и пути развития в продакшн](#10-ограничения-mvp-и-пути-развития-в-продакшн)

---

## 1. Архитектура и модель угроз

Проект разделён на три слоя с проверкой прав на каждом уровне:

* **Клиентский слой (`index.html`):** одностраничный интерфейс на Tailwind CSS и vanilla JS. Скрывает и блокирует элементы управления в зависимости от роли пользователя, но **не является границей безопасности** — любая привилегированная операция повторно проверяется сервером по токену сессии.
* **Прикладной слой (`main.py` + `security.py`):** FastAPI-приложение (`version="7.0-FINAL"`), управляющее сессиями (`Bearer`), жизненным циклом заявок на счета, переводами, правилами Anti-Fraud, выдачей/проверкой OTP-кодов, Kill Switch, проверкой хеш-цепочки и выгрузкой подписанных JSON-отчётов.
* **Слой хранения (`database.py` + `securefin_core.db`):** SQLite в режиме `WAL` с включёнными внешними ключами (`PRAGMA foreign_keys = ON`), ограничениями `CHECK`, триггерами аудита изменений и представлением `v_transactions_overview`.

### Какие угрозы закрывает проект

* **Самоповышение привилегий при регистрации:** открытая форма подачи заявки создаёт запись со статусом `PENDING` и при одобрении выдаёт только роль `CLIENT`. Выдать себе роль `OPERATOR`, `SECURITY_OFFICER` или `AUDITOR` через API или форму невозможно.
* **Горизонтальная эскалация доступа (IDOR):** клиент может запрашивать баланс/лимиты (`/account/{user_id}`), историю операций (`/my-transactions`) и инициировать переводы (`/transfer`) только в рамках своего аккаунта.
* **Двойное списание при ретраях и сетевых сбоях:** поддерживается ключ идемпотентности `idempotency_key` (`UNIQUE` в таблице `transactions`). Повторный запрос с тем же ключом возвращает сохранённый результат (`IDEMPOTENT_REPLAY`) без повторного списания.
* **Race condition при параллельных переводах:** операции изменения балансов, лимитов, заявок и настроек выполняются внутри транзакций `BEGIN IMMEDIATE` с откатом (`ROLLBACK`) при любой ошибке.
* **Утечка открытых балансов при дампе БД:** балансы шифруются через `Fernet` (`security.py`) и хранятся в `accounts.encrypted_balance` в виде шифротекста. Ключ шифрования сохраняется в файле `secret.key`.
* **Подделка записей журнала аудита задним числом:** каждая запись в `audit_logs` включает `prev_hash` и `record_hash` (`SHA-256`). Любое изменение или удаление строки ломает цепочку, что выявляет эндпоинт `/db-chain-check`.

---

## 2. Быстрый старт и запуск

### Шаг 1. Установка зависимостей
Откройте терминал в корневой директории проекта (`FINVVV-main`) и установите пакеты:

```bash
pip install fastapi uvicorn cryptography pydantic httpx
```
*(Если используете `requirements.txt`, убедитесь, что в нём указаны эти же зависимости, включая `httpx` для запуска `TestClient`.)*

### Шаг 2. Запуск бэкенда FastAPI
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Что происходит при старте приложения (`@app.on_event("startup")`):
1. Вызывается `init_db()` из `database.py` (в транзакции `BEGIN IMMEDIATE`).
2. Создаются 12 таблиц, ограничения `CHECK`, триггеры `trigger_tamper_protection` и `trigger_account_history`, а также представление `v_transactions_overview`.
3. Вызывается `ensure_default_staff(cursor)` — создаются штатные сотрудники банка (`soc_officer`, `bank_operator`, `chief_auditor`), если их ещё нет в таблице `users`.

Проверка доступности API:
* Корень API: `http://127.0.0.1:8000/` (ожидается статус `"ARMED & OPERATIONAL"`).
* Интерактивная документация Swagger UI: `http://127.0.0.1:8000/docs`.

### Шаг 3. Запуск фронтенда (`index.html`)
Откройте **второе окно терминала** в папке проекта и запустите статический HTTP-сервер:

```bash
python -m http.server 5500
```

Откройте в браузере:
```text
[http://127.0.0.1:5500/index.html](http://127.0.0.1:5500/index.html)
```

> **CORS и адреса по умолчанию:** в `main.py` разрешены origins `http://127.0.0.1:5500`, `http://localhost:5500`, `http://127.0.0.1:8000`, `http://localhost:8000` и `null` (переопределяется переменной окружения `ALLOWED_ORIGINS`).

### Шаг 4. Запуск интеграционных тестов
```bash
python test_security.py
```
Тест использует отдельную временную базу `test_securefin.db`, прогоняет 8 сценариев безопасности и удаляет тестовые файлы БД (`test_securefin.db`, `-wal`, `-shm`) после завершения.

> **Сброс локальной БД при изменении схемы:** остановите `uvicorn` (`Ctrl + C`), удалите `securefin_core.db` (и при наличии `securefin_core.db-wal`, `securefin_core.db-shm`) и запустите сервер заново.

---

## 3. Роли, учётные записи и матрица доступа (RBAC)

При инициализации БД автоматически создаются 3 учётные записи персонала:

| Роль | Логин | Пароль | Стартовый баланс | Дневной лимит | Назначение |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `OPERATOR` | `bank_operator` | `op123` | `500 000 KZT` | `300 000 KZT` | Работа с заявками клиентов, прямое открытие счетов, переводы, просмотр журналов |
| `SECURITY_OFFICER` | `soc_officer` | `soc123` | `1 000 000 KZT` | `500 000 KZT` | Полный контур ИБ: включение/выключение Kill Switch (`DEFCON 1`), закрытие инцидентов, заявки, переводы |
| `AUDITOR` | `chief_auditor` | `aud123` | `250 000 KZT` | `100 000 KZT` | Контроль целостности хеш-цепочки (`/db-chain-check`), просмотр логов/инцидентов, выгрузка отчётов |
| `CLIENT` | *по заявке* | *задаётся клиентом* | *из заявки / открытия* | *из заявки / открытия* | Просмотр только своего счёта и своих транзакций, исходящие переводы со своего счёта |

### Матрица прав по ключевым операциям

| Функция / Эндпоинт | Гость (без токена) | `CLIENT` | `OPERATOR` | `SECURITY_OFFICER` | `AUDITOR` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `POST /applications` (подача заявки) | Да | — | — | — | — |
| `POST /auth/login` | Да | Да | Да | Да | Да |
| `GET /applications`, `approve`, `reject` | Нет (`401`) | Нет (`403`) | Да | Да | Нет (`403`) |
| `POST /clients/open` | Нет (`401`) | Нет (`403`) | Да | Да | Нет (`403`) |
| `GET /account/{user_id}` | Нет (`401`) | Только свой (`403` за чужой) | Любой | Любой | Любой |
| `POST /transfer` | Нет (`401`) | Только со своего счёта (`403` за чужой) | Да | Да | Нет (`403`) |
| `POST /emergency-lockdown` | Нет (`401`) | Нет (`403`) | Нет (`403`) | Да | Нет (`403`) |
| `POST /incidents/{id}/resolve` | Нет (`401`) | Нет (`403`) | Нет (`403`) | Да | Нет (`403`) |
| `GET /audit-logs`, `/incidents`, `/blocked-ips`, `/stats`, `/db-chain-check`, `/export-report` | Нет (`401`) | Нет (`403`) | Да | Да | Да |

---

## 4. Схема базы данных, ограничения, триггеры и VIEW

В `database.py` создаётся 12 таблиц:

1. **`system_settings`** — ключ-значение настроек системы (в частности `system_lockdown`: `'0'` или `'1'`).
2. **`otp_codes`** — одноразовые коды 2FA (`user_id` PK, `code`, `expires_at`, каскадное удаление при удалении пользователя).
3. **`users`** — пользователи (`id`, `username` UNIQUE, `password_hash`, `role` с проверкой `CHECK (role IN ('CLIENT', 'OPERATOR', 'SECURITY_OFFICER', 'AUDITOR'))`, `created_at`).
4. **`account_applications`** — заявки на открытие счёта (`applicant_username` UNIQUE, `password_hash`, `requested_balance >= 0`, `requested_limit > 0`, `status` в `PENDING` / `APPROVED` / `REJECTED`, `reviewed_by`, `created_at`, `reviewed_at`).
5. **`sessions`** — активные токен-сессии (`token` PK, `user_id` FK с `ON DELETE CASCADE`, `created_at`).
6. **`accounts`** — банковские счета (`id`, `user_id` FK, `encrypted_balance`, `currency` по умолчанию `'KZT'`, `daily_limit > 0`, `updated_at`).
7. **`transactions`** — журнал переводов (`id`, `idempotency_key` UNIQUE, `sender_account_id`, `receiver_account_id`, `amount > 0`, `status` в `SUCCESS` / `BLOCKED`, `risk_score` от `0` до `100`, `created_at`).
8. **`audit_logs`** — неизменяемый журнал событий с хеш-цепочкой (`id`, `user_id`, `action`, `details`, `prev_hash`, `record_hash`, `created_at`).
9. **`db_trigger_events`** — события триггера обновления таблицы `accounts`.
10. **`account_history`** — история старых и новых зашифрованных балансов при изменении `encrypted_balance`.
11. **`blocked_ips`** — заблокированные IP-адреса (`ip_address` UNIQUE, `geo_info`, `reason`, `blocked_at`).
12. **`incidents`** — инциденты безопасности (`incident_type`, `severity` в `MEDIUM` / `HIGH` / `CRITICAL`, `status` в `OPEN` / `RESOLVED`, `summary`, `source_ip`, `created_at`, `resolved_at`).

### Триггеры и представление (`VIEW`)

* **`trigger_tamper_protection`** (`AFTER UPDATE ON accounts`) — записывает в `db_trigger_events` факт обновления записи счёта (`user_id` и текущее значение `daily_limit`).
* **`trigger_account_history`** (`AFTER UPDATE OF encrypted_balance ON accounts`) — сохраняет в `account_history` пару `old_encrypted_balance` и `new_encrypted_balance`.
* **`v_transactions_overview`** — представление (`VIEW`), объединяющее `transactions` и `users` (через `accounts`) для удобного просмотра `tx_id`, `idempotency_key`, `sender_username`, `receiver_username`, `amount`, `status`, `risk_score` и `created_at`.

---

## 5. Криптография, 2FA и защита от гонки запросов

### Шифрование и хеширование (`security.py`)
* **`encrypt_data` / `decrypt_data`:** используют `cryptography.fernet.Fernet` с ключом из файла `secret.key` (если файла нет — генерируется новый при первом запуске). Важно: файл `secret.key` нужен для расшифровки уже записанных в БД балансов; при переносе БД на другую машину переносите и `secret.key`.
* **`hash_password` / `verify_password`:** вычисляют `SHA-256` от пароля.

### Двухфакторная аутентификация (`2FA`)
* При переводе на сумму **больше `100 000 KZT`** (для обычных/клиентских переводов, не `is_red_team`) без переданного `otp_code` сервер генерирует 6-значный код через `secrets.randbelow`, сохраняет его в таблице `otp_codes` со сроком действия **5 минут** (`expires_at`) и возвращает `HTTP 401` (`status: "2FA_REQUIRED"`, `demo_otp_push`).
* При повторной отправке с корректным кодом код проверяется через `secrets.compare_digest` и **сразу удаляется** из `otp_codes` (одноразовое использование).

### Аварийный Kill Switch (`DEFCON 1`)
* Состояние хранится в таблице `system_settings` (`key = 'system_lockdown'`), поэтому сохраняется между перезапусками сервера.
* Включение (`POST /emergency-lockdown` от `SECURITY_OFFICER`) блокирует переводы (`HTTP 403`), пишет запись `DEFCON_1_LOCKDOWN` в `audit_logs` и открывает критический инцидент `EMERGENCY_LOCKDOWN` (`CRITICAL`, `OPEN`).
* Повторный вызов отключает режим изоляции, пишет `DEFCON_RESTORED` и переводит открытые инциденты `EMERGENCY_LOCKDOWN` в статус `RESOLVED`.

---

## 6. Жизненный цикл перевода и Anti-Fraud скоринг

При вызове `POST /transfer` внутри транзакции `BEGIN IMMEDIATE` проверки выполняются в следующем порядке:

1. **Режим изоляции (`DEFCON 1`):** если `system_lockdown == '1'`, возвращается `403`.
2. **Идентификация отправителя / Red Team:** при `is_red_team=True` выбирается адрес из списка `THREAT_ORIGINS` и задаётся отправитель `EXTERNAL_RED_TEAM`; в штатном режиме требуется токен `CLIENT`, `OPERATOR` или `SECURITY_OFFICER`, а для `CLIENT` проверяется совпадение `actor["id"] == transfer.sender_user_id`.
3. **Идемпотентность (`idempotency_key`):** если транзакция с таким `idempotency_key` уже существует в `transactions`, возвращается ответ со статусом `IDEMPOTENT_REPLAY` без повторного списания.
4. **Проверка IP в чёрном списке (`blocked_ips`):** если IP отправителя уже заблокирован в БД, возвращается `403`.
5. **Валидация параметров и счетов:** проверяются `amount > 0`, `sender_user_id != receiver_user_id` и наличие счетов у отправителя и получателя (`404` при отсутствии).
6. **Контроль дневного лимита (`daily_limit`):** для не-Red-Team переводов суммируются успешные (`SUCCESS`) переводы отправителя за текущую дату (`date(created_at) = date('now')`); при превышении `daily_limit` пишется событие `DAILY_LIMIT_EXCEEDED` и возвращается `403`.
7. **2FA (`amount > 100 000 KZT`):** проверка наличия и валидности одноразового OTP-кода.
8. **Расчёт `risk_score` (ограничивается максимумом `100`):**
   * `+100` — недостаточно средств (`sender_balance < transfer.amount`);
   * `+50` — сумма перевода превышает `500 000 KZT` (`High-value anomaly (>500k KZT)`);
   * `+45` — режим симуляции атаки (`is_red_team=True`, `Suspicious ASN`);
   * `+85` — 3 и более транзакций от этого счёта за последнюю минуту (`Velocity threshold breached`).
9. **Блокировка или проведение перевода:**
   * Если `risk_score >= 80` или не хватает средств: транзакция пишется со статусом `BLOCKED`, IP добавляется в `blocked_ips`, создаётся инцидент `FRAUD_ATTEMPT_BLOCKED` (`HIGH` при `risk_score < 95`, иначе `CRITICAL`), в `audit_logs` пишется `FRAUD_BLOCKED`, возвращается `403`.
   * Если перевод разрешён: пересчитываются и шифруются балансы обоих счетов, обновляется таблица `accounts` (запускаются триггеры SQLite), создаётся транзакция `SUCCESS` и запись `TRANSFER_SUCCESS` в `audit_logs`.

---

## 7. Справочник HTTP-эндпоинтов API

| Метод | Путь | Доступ | Краткое описание |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Публичный | Статус сервиса, флаг `system_lockdown`, счётчики открытых инцидентов, заявок и заблокированных IP |
| `POST` | `/applications` | Публичный | Подача заявки клиента на открытие счёта (`PENDING`) |
| `GET` | `/applications` | `OPERATOR`, `SECURITY_OFFICER` | Список заявок на открытие счёта |
| `POST` | `/applications/{app_id}/approve` | `OPERATOR`, `SECURITY_OFFICER` | Одобрение заявки, создание пользователя `CLIENT` и зашифрованного счёта |
| `POST` | `/applications/{app_id}/reject` | `OPERATOR`, `SECURITY_OFFICER` | Отклонение заявки (`REJECTED`) |
| `POST` | `/clients/open` | `OPERATOR`, `SECURITY_OFFICER` | Прямое создание клиентского аккаунта и счёта сотрудником |
| `POST` | `/auth/login` | Публичный | Аутентификация по логину/паролю, выдача `Bearer`-токена и запись `USER_LOGIN` / `LOGIN_FAILED` |
| `GET` | `/auth/me` | Любая сессия | Проверка токена, данных пользователя и текущего `system_lockdown` |
| `POST` | `/auth/logout` | Любая сессия | Удаление сессии и запись `USER_LOGOUT` |
| `GET` | `/users` | Персонал и `AUDITOR` | Реестр пользователей, ролей и дневных лимитов |
| `GET` | `/my-transactions` | Любая сессия | Последние 25 входящих/исходящих транзакций текущего пользователя |
| `GET` | `/db-chain-check` | Персонал и `AUDITOR` | Проверка хеш-цепочки `audit_logs`, число срабатываний триггеров и срез `v_transactions_overview` |
| `POST` | `/emergency-lockdown` | `SECURITY_OFFICER` | Переключение `system_lockdown` (`0` / `1`) и управление инцидентом `EMERGENCY_LOCKDOWN` |
| `POST` | `/update-limit` | `OPERATOR`, `SECURITY_OFFICER` | Изменение `daily_limit` счёта пользователя |
| `GET` | `/account/{user_id}` | Любая сессия (клиент — только свой) | Расшифрованный баланс, дневной лимит, потрачено сегодня и превью шифротекста |
| `POST` | `/request-otp` | Любая сессия (клиент — только свой) | Генерация и сохранение OTP-кода в БД (TTL 300 сек) |
| `POST` | `/transfer` | `CLIENT`, `OPERATOR`, `SECURITY_OFFICER` (или `is_red_team=True`) | Атомарный перевод с проверками лимитов, 2FA, идемпотентности и Anti-Fraud |
| `GET` | `/incidents` | Персонал и `AUDITOR` | Последние 20 инцидентов безопасности |
| `POST` | `/incidents/{incident_id}/resolve` | `SECURITY_OFFICER` | Перевод инцидента в статус `RESOLVED` |
| `GET` | `/audit-logs` | Персонал и `AUDITOR` | Последние 35 записей журнала аудита |
| `GET` | `/blocked-ips` | Персонал и `AUDITOR` | Список заблокированных IP-адресов из `blocked_ips` |
| `GET` | `/stats` | Персонал и `AUDITOR` | Метрики SOC (успешные, блокировки, оборот, пик риска, IP в блеклисте, открытые инциденты) |
| `GET` | `/export-report` | Персонал и `AUDITOR` | Выгрузка полного JSON-отчёта с контрольной суммой `SHA-256` (`cryptographic_seal_sha256`) |

---

## 8. Режимы работы веб-интерфейса (`index.html`)

* **Экран входа и заявок (`#authScreen`):** вход