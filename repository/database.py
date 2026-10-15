import os
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = Path(
    os.environ.get("DEVSECOPS_DATABASE_PATH", str(BASE_DIR / "devsecops.db"))
).expanduser()


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=15,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def initialize_database():
    connection = get_connection()

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_scan TEXT,
                score INTEGER,
                grade TEXT,
                status TEXT,
                reason TEXT,
                findings INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_id INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                findings INTEGER NOT NULL,

                FOREIGN KEY (
                    repository_id
                )
                REFERENCES repositories(id)
                ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                scanner TEXT,
                category TEXT,
                severity TEXT,
                confidence TEXT,
                file TEXT,
                line INTEGER,
                rule_id TEXT,
                message TEXT,
                cwe TEXT,

                FOREIGN KEY (
                    scan_id
                )
                REFERENCES scans(id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS
            idx_scans_repository_id
            ON scans(repository_id);

            CREATE INDEX IF NOT EXISTS
            idx_findings_scan_id
            ON findings(scan_id);

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('superuser', 'operator', 'viewer')),
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
            ON auth_sessions(user_id);

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
            ON auth_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS auth_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                peer_ip TEXT NOT NULL,
                attempted_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_username_time
            ON auth_login_attempts(username, attempted_at);

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_peer_time
            ON auth_login_attempts(peer_ip, attempted_at);

            CREATE TABLE IF NOT EXISTS auth_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                actor_username TEXT NOT NULL,
                target_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                target_username TEXT NOT NULL,
                action TEXT NOT NULL,
                changes TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        connection.commit()

    finally:
        connection.close()
