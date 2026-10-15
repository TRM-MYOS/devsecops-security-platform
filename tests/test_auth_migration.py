"""Auth schema migration must preserve pre-existing platform data."""

import importlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


LEGACY_SCHEMA = """
CREATE TABLE repositories (
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
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL,
    scanned_at TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    findings INTEGER NOT NULL,
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);
CREATE TABLE findings (
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
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
"""


def test_auth_migration_is_idempotent_and_preserves_existing_data(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy-platform.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO repositories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (7, "legacy-repository", "https://github.com/TRM-MYOS/legacy", "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", 65, "C", "BLOCK", "High severity finding", 1),
        )
        connection.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (11, 7, "2025-01-02T00:00:00Z", 65, "C", "BLOCK", "High severity finding", 1),
        )
        connection.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (15, 11, "Bandit", "code", "HIGH", "HIGH", "app.py", 42, "B602", "Unsafe shell command", "CWE-78"),
        )
        before = {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in ("repositories", "scans", "findings")
        }
    monkeypatch.setenv("DEVSECOPS_DATABASE_PATH", str(database_path))
    database = importlib.import_module("repository.database")
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    database.initialize_database()
    database.initialize_database()
    with database.get_connection() as connection:
        after = {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()]
            for table in before
        }
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {"users", "auth_sessions"} <= tables
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert after == before


def test_production_disables_public_api_documentation_in_fresh_process(tmp_path):
    database_path = tmp_path / "production-docs.db"
    environment = {
        **os.environ,
        "DEVSECOPS_DATABASE_PATH": str(database_path),
        "DEVSECOPS_ENV": "production",
        "DEVSECOPS_COOKIE_SECURE": "true",
        "DEVSECOPS_ALLOWED_ORIGINS": "https://security.example.com",
    }
    code = """
import os
from pathlib import Path
from fastapi.testclient import TestClient
from api.app import app
from repository.database import DATABASE_PATH
assert DATABASE_PATH.resolve() == Path(os.environ["DEVSECOPS_DATABASE_PATH"]).resolve()
assert app.docs_url is None
assert app.redoc_url is None
assert app.openapi_url is None
with TestClient(app, base_url="https://security.example.com") as client:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path
    assert client.get("/health").status_code == 200
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parent.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
