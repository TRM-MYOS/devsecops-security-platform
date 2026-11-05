"""Tests must never start a real background GitHub synchronization worker."""

import pytest


@pytest.fixture(autouse=True)
def disable_live_github_polling(monkeypatch):
    monkeypatch.setenv("DEVSECOPS_GITHUB_POLL_ENABLED", "false")


@pytest.fixture(autouse=True)
def isolate_default_database(tmp_path, monkeypatch):
    """Configuration lookups must never read settings from the real database."""
    from repository import database
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "default-test.db")
