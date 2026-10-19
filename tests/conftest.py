"""Tests must never start a real background GitHub synchronization worker."""

import pytest


@pytest.fixture(autouse=True)
def disable_live_github_polling(monkeypatch):
    monkeypatch.setenv("DEVSECOPS_GITHUB_POLL_ENABLED", "false")
