import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "devsecops.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
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
            """
        )

        connection.commit()

    finally:
        connection.close()