"""Scan API failure boundaries, using temporary reports and an isolated database."""

import importlib
import json
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def scan_environment(tmp_path, monkeypatch):
    database_path = tmp_path / "scan-api.db"
    monkeypatch.setenv("DEVSECOPS_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("DEVSECOPS_ENV", "development")
    monkeypatch.setenv("DEVSECOPS_COOKIE_SECURE", "false")
    database = importlib.import_module("repository.database")
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    api = importlib.import_module("api.app")
    manager = api.RepositoryManager()
    monkeypatch.setattr(api, "repository_manager", manager)
    service = importlib.import_module("auth.service")
    password = "Scan-api-test-password-123!"
    service.bootstrap_superuser("scan-admin", password)
    repositories = [
        manager.add_repository(f"https://github.com/TRM-MYOS/scan-test-{index}")
        for index in range(2)
    ]
    cleanup = Mock()
    scans = []
    reports = {
        "bandit": {"results": [], "errors": []},
        "trivy": {
            "SchemaVersion": 2, "ArtifactName": "target", "ArtifactType": "filesystem",
        },
        "gitleaks": [],
    }

    def clone(url):
        directory = tmp_path / f"execution-{len(scans)}"
        directory.mkdir()
        scans.append(url)
        return {
            "temp_dir": type("Temp", (), {"name": str(directory), "cleanup": cleanup})(),
            "repo_path": directory / "target",
        }

    def scan(target, directory):
        directory.mkdir()
        for name, data in reports.items():
            (directory / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
        return {
            name: {"returncode": 0, "stdout": "", "stderr": ""}
            for name in reports
        }

    monkeypatch.setattr(manager, "scan_repository", clone)
    monkeypatch.setattr(api, "run_security_scan", scan)
    return api, manager, repositories, reports, scan, scans, cleanup, password


@pytest.fixture
def scan_client(scan_environment):
    api, *_, password = scan_environment
    with TestClient(api.app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login",
            json={"username": "scan-admin", "password": password},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        yield client


@pytest.mark.parametrize("blocked", [False, True])
def test_scan_preserves_real_policy_and_persists_findings(scan_environment, scan_client, blocked):
    _, manager, repositories, reports, _, _, cleanup, _ = scan_environment
    if blocked:
        reports["gitleaks"] = [
            {"File": "app.py", "RuleID": "test-secret", "Description": "Synthetic", "StartLine": 1}
        ]
    response = scan_client.post(f"/api/repositories/{repositories[0]['id']}/scan")
    assert response.status_code == 200
    result = response.json()
    assert (result["status"], result["score"], result["grade"]) == (
        ("BLOCK", 75, "C") if blocked else ("ALLOW", 100, "A")
    )
    assert len(manager.get_scan_history(repositories[0]["id"])) == 1
    assert len(manager.get_scan_findings(result["scan_id"])) == int(blocked)
    cleanup.assert_called_once()


@pytest.mark.parametrize("scanner", ["bandit", "trivy", "gitleaks"])
@pytest.mark.parametrize("failure", ["missing", "empty", "invalid_json", "invalid_schema"])
def test_bad_report_returns_error_without_persisting_allow(
    scan_environment, scan_client, monkeypatch, scanner, failure,
):
    api, manager, repositories, _, original_scan, _, cleanup, _ = scan_environment

    def broken_scan(target, directory):
        result = original_scan(target, directory)
        report = directory / f"{scanner}.json"
        if failure == "missing":
            report.unlink()
        else:
            report.write_text(
                {"empty": "", "invalid_json": "{", "invalid_schema": "null"}[failure],
                encoding="utf-8",
            )
        return result

    monkeypatch.setattr(api, "run_security_scan", broken_scan)
    response = scan_client.post(f"/api/repositories/{repositories[0]['id']}/scan")
    assert response.status_code == 500
    assert "Report Validation Failure" in response.json()["detail"]
    assert scanner.lower() in response.json()["detail"].lower()
    assert "status" not in response.json()
    assert manager.get_all_scans() == []
    assert manager.get_repository(repositories[0]["id"])["status"] is None
    cleanup.assert_called_once()


def test_bandit_errors_are_report_failure(scan_environment, scan_client):
    _, manager, repositories, reports, _, _, cleanup, _ = scan_environment
    reports["bandit"]["errors"] = [{"filename": "app.py", "reason": "syntax error"}]
    response = scan_client.post(f"/api/repositories/{repositories[0]['id']}/scan")
    assert response.status_code == 500
    assert "Bandit errors" in response.json()["detail"]
    assert manager.get_all_scans() == []
    cleanup.assert_called_once()


@pytest.mark.parametrize("failure", ["report", "scanner", "executable"])
def test_scan_all_continues_after_failure(scan_environment, scan_client, monkeypatch, failure):
    api, manager, _, _, original_scan, scans, cleanup, _ = scan_environment
    order = manager.get_repositories()

    def fail_first(target, directory):
        if len(scans) == 1:
            if failure == "scanner":
                raise RuntimeError("Scanner Failure: trivy: returncode=1")
            if failure == "executable":
                raise FileNotFoundError("gitleaks executable missing")
            result = original_scan(target, directory)
            (directory / "bandit.json").write_text("{", encoding="utf-8")
            return result
        return original_scan(target, directory)

    monkeypatch.setattr(api, "run_security_scan", fail_first)
    response = scan_client.post("/api/repositories/scan-all")
    assert response.status_code == 200
    result = response.json()
    assert (result["total"], result["successful"], result["failed"]) == (2, 1, 1)
    first, second = result["results"]
    assert first["status"] == "failed" and first["error"]
    assert "scan" not in first
    assert second["status"] == "success" and second["scan"]["status"] == "ALLOW"
    assert manager.get_scan_history(order[0]["id"]) == []
    assert len(manager.get_scan_history(order[1]["id"])) == 1
    assert cleanup.call_count == 2


def test_single_scanner_failure_returns_json_error(scan_environment, scan_client, monkeypatch):
    api, manager, repositories, _, _, _, cleanup, _ = scan_environment
    monkeypatch.setattr(api, "run_security_scan", Mock(side_effect=RuntimeError("Scanner Failure: trivy")))
    response = scan_client.post(f"/api/repositories/{repositories[0]['id']}/scan")
    assert response.status_code == 500
    assert "Scanner Failure: trivy" in response.json()["detail"]
    assert manager.get_all_scans() == []
    cleanup.assert_called_once()


def test_missing_repository_stays_404(scan_environment, scan_client):
    response = scan_client.post("/api/repositories/999999/scan")
    assert response.status_code == 404


def test_cli_parser_report_failure_still_exits_nonzero(tmp_path):
    from security.parser import main

    with pytest.raises(SystemExit) as failure:
        main(tmp_path)
    assert failure.value.code != 0
