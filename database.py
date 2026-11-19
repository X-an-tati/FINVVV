import sqlite3

DB_NAME = "securefin_core.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Пользователи с ролевой моделью (CLIENT / OPERATOR / SECURITY_OFFICER / AUDITOR)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'CLIENT' CHECK (role IN ('CLIENT', 'OPERATOR', 'SECURITY_OFFICER', 'AUDITOR')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Счета с дневным лимитом расходных операций
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_balance TEXT NOT NULL,
            currency TEXT NOT NULL DEFAULT 'KZT',
            daily_limit REAL NOT NULL DEFAULT 300000.0 CHECK (daily_limit > 0),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Транзакции с уникальным idempotency_key для защиты от двойного списания
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idempotency_key TEXT UNIQUE,
            sender_account_id INTEGER NOT NULL,
            receiver_account_id INTEGER NOT NULL,
            amount REAL NOT NULL CHECK (amount > 0),
            status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'BLOCKED')),
            risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Хеш-цепочка аудита
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Неизменяемая история изменения счетов
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS account_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            old_encrypted_balance TEXT NOT NULL,
            new_encrypted_balance TEXT NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Персистентный черный список IP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            geo_info TEXT,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Журнал инцидентов и разборов (Incident Timeline)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'RESOLVED')),
            summary TEXT NOT NULL,
            source_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP
        )
    """)

    # Защитный триггер при прямом изменении таблицы accounts в обход приложения
    cursor.execute("DROP TRIGGER IF EXISTS trigger_tamper_protection;")
    cursor.execute("""
        CREATE TRIGGER trigger_tamper_protection
        AFTER UPDATE ON accounts
        BEGIN
            INSERT INTO audit_logs (user_id, action, details, prev_hash, record_hash)
            VALUES (
                NEW.user_id,
                'DB_TRIGGER_ACCOUNT_UPDATED',
                'Зафиксировано обновление строки в таблице accounts на уровне SQLite.',
                'TRIGGER',
                'TRIGGER_HASH'
            );
        END;
    """)

    # Триггер истории изменения баланса
    cursor.execute("DROP TRIGGER IF EXISTS trigger_account_history;")
    cursor.execute("""
        CREATE TRIGGER trigger_account_history
        AFTER UPDATE OF encrypted_balance ON accounts
        BEGIN
            INSERT INTO account_history (account_id, old_encrypted_balance, new_encrypted_balance)
            VALUES (OLD.id, OLD.encrypted_balance, NEW.encrypted_balance);
        END;
    """)

    # Наглядное SQL VIEW: объединяет транзакции, логины отправителей и получателей
    cursor.execute("DROP VIEW IF EXISTS v_transactions_overview;")
    cursor.execute("""
        CREATE VIEW v_transactions_overview AS
        SELECT
            t.id AS tx_id,
            t.idempotency_key,
            u_send.username AS sender_username,
            u_recv.username AS receiver_username,
            t.amount,
            t.status,
            t.risk_score,
            t.created_at
        FROM transactions t
        LEFT JOIN accounts a_send ON t.sender_account_id = a_send.id
        LEFT JOIN users u_send ON a_send.user_id = u_send.id
        LEFT JOIN accounts a_recv ON t.receiver_account_id = a_recv.id
        LEFT JOIN users u_recv ON a_recv.user_id = u_recv.id;
    """)

    conn.commit()
    cursor.close()
    conn.close()