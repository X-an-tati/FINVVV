import sqlite3
from security import hash_password, encrypt_data

DB_NAME = "securefin_core.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def ensure_default_staff(cursor):
    default_staff = [
        ("soc_officer", "soc123", "SECURITY_OFFICER", 1000000.0, 500000.0),
        ("bank_operator", "op123", "OPERATOR", 500000.0, 300000.0),
        ("chief_auditor", "aud123", "AUDITOR", 250000.0, 100000.0),
    ]
    for uname, raw_pwd, role, bal, limit in default_staff:
        cursor.execute("SELECT id FROM users WHERE username = ?", (uname,))
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (uname, hash_password(raw_pwd), role),
            )
            uid = cursor.lastrowid
            cursor.execute(
                "INSERT INTO accounts (user_id, encrypted_balance, daily_limit) VALUES (?, ?, ?)",
                (uid, encrypt_data(str(bal)), limit),
            )
        else:
            uid = row["id"]
            cursor.execute("SELECT id FROM accounts WHERE user_id = ?", (uid,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO accounts (user_id, encrypted_balance, daily_limit) VALUES (?, ?, ?)",
                    (uid, encrypt_data(str(bal)), limit),
                )


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("BEGIN IMMEDIATE;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO system_settings (key, value)
        VALUES ('system_lockdown', '0')
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            user_id INTEGER PRIMARY KEY,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'CLIENT' CHECK (role IN ('CLIENT', 'OPERATOR', 'SECURITY_OFFICER', 'AUDITOR')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS account_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            applicant_username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            requested_balance REAL NOT NULL DEFAULT 300000.0 CHECK (requested_balance >= 0),
            requested_limit REAL NOT NULL DEFAULT 300000.0 CHECK (requested_limit > 0),
            status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
            reviewed_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            FOREIGN KEY (reviewed_by) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS db_trigger_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            row_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS account_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            old_encrypted_balance TEXT NOT NULL,
            new_encrypted_balance TEXT NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            geo_info TEXT,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

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

    cursor.execute("DROP TRIGGER IF EXISTS trigger_tamper_protection;")
    cursor.execute("""
        CREATE TRIGGER trigger_tamper_protection
        AFTER UPDATE ON accounts
        BEGIN
            INSERT INTO db_trigger_events (table_name, row_id, event_type, details)
            VALUES (
                'accounts',
                NEW.id,
                'AFTER_UPDATE',
                'Обновлена запись счёта user_id=' || NEW.user_id || ', daily_limit=' || NEW.daily_limit
            );
        END;
    """)

    cursor.execute("DROP TRIGGER IF EXISTS trigger_account_history;")
    cursor.execute("""
        CREATE TRIGGER trigger_account_history
        AFTER UPDATE OF encrypted_balance ON accounts
        BEGIN
            INSERT INTO account_history (account_id, old_encrypted_balance, new_encrypted_balance)
            VALUES (OLD.id, OLD.encrypted_balance, NEW.encrypted_balance);
        END;
    """)

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

    ensure_default_staff(cursor)

    cursor.execute("COMMIT;")
    cursor.close()
    conn.close()