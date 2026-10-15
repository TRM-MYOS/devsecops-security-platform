"""The interactive bootstrap creates only the first account and never echoes passwords."""

import importlib

import pytest


@pytest.fixture
def bootstrap_environment(tmp_path, monkeypatch):
    database_path = tmp_path / "bootstrap.db"
    monkeypatch.setenv("DEVSECOPS_DATABASE_PATH", str(database_path))
    database = importlib.import_module("repository.database")
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    bootstrap = importlib.import_module("auth.bootstrap")
    monkeypatch.setattr("sys.argv", ["auth.bootstrap", "--username", "first-admin"])
    return bootstrap, database


def test_bootstrap_creates_first_superuser_and_refuses_to_overwrite(bootstrap_environment, monkeypatch, capsys):
    bootstrap, database = bootstrap_environment
    password = "Bootstrap-test-only-password!"
    monkeypatch.setattr(bootstrap.getpass, "getpass", lambda prompt: password)
    assert bootstrap.main() == 0
    with database.get_connection() as connection:
        original = tuple(connection.execute("SELECT username, password_hash, role FROM users").fetchone())
    assert original[0] == "first-admin"
    assert original[1].startswith("$argon2id$")
    assert original[2] == "superuser"
    assert bootstrap.main() == 1
    with database.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert tuple(connection.execute("SELECT username, password_hash, role FROM users").fetchone()) == original
    output = capsys.readouterr()
    assert password not in output.out + output.err
    assert "Accounts already exist" in output.err


def test_bootstrap_mismatched_passwords_create_no_account(bootstrap_environment, monkeypatch, capsys):
    bootstrap, database = bootstrap_environment
    answers = iter(["Bootstrap-test-only-password!", "Different-test-only-password!"])
    monkeypatch.setattr(bootstrap.getpass, "getpass", lambda prompt: next(answers))
    assert bootstrap.main() == 1
    database.initialize_database()
    with database.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    assert "Passwords do not match" in capsys.readouterr().err
