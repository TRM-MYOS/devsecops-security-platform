import pytest

import repository.database as database
from repository.repository_manager import RepositoryManager


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "repositories.db")
    return RepositoryManager()


def test_add_duplicate_preserves_repository(manager):
    repository = manager.add_repository("https://github.com/TRM-MYOS/example.git")
    duplicate = manager.add_repository(repository["url"])
    assert duplicate["id"] == repository["id"]
    assert repository["name"] == "example"
    assert len(manager.get_repositories()) == 1


def test_save_history_and_delete_cascades_findings(manager):
    repository = manager.add_repository("https://github.com/TRM-MYOS/example")
    finding = {"scanner": "Bandit", "severity": "HIGH", "file": "app.py", "line": 8, "message": "Unsafe call"}
    scan_id = manager.save_scan(repository["id"], "2026-10-13T00:00:00+00:00", 75, "C", "BLOCK", "High vulnerability detected", [finding])
    saved = manager.get_repository(repository["id"])
    assert (saved["score"], saved["status"], saved["findings"]) == (75, "BLOCK", 1)
    assert manager.get_scan_history(repository["id"])[0]["id"] == scan_id
    assert manager.get_all_scans()[0]["repository_name"] == "example"
    assert manager.get_scan_findings(scan_id)[0]["message"] == "Unsafe call"
    assert manager.delete_repository(repository["id"]) is True
    assert manager.get_scan_history(repository["id"]) == []
    assert manager.get_scan_findings(scan_id) == []
    assert manager.delete_repository(repository["id"]) is False
