"""Monitoring endpoints use authentication and never launch local scanners."""

from unittest.mock import Mock

from test_scan_api import scan_environment, scan_client
from test_github_monitor import Client


def test_sync_api_imports_results_without_local_scan(scan_environment, scan_client, monkeypatch):
    api, manager, repositories, *_ = scan_environment
    monkeypatch.setattr(api.github_monitor, "GitHubClient", Client)
    scanner = Mock(side_effect=AssertionError("Local scanners must not run"))
    monkeypatch.setattr(api, "run_security_scan", scanner)
    rid = repositories[0]["id"]
    response = scan_client.post(f"/api/repositories/{rid}/sync")
    assert response.status_code == 200 and response.json()["branches"][0]["policy_status"] == "ALLOW"
    listing = scan_client.get("/api/repositories").json()["repositories"]
    assert next(r for r in listing if r["id"] == rid)["tracking"]["branches"][0]["commit_sha"]
    history = scan_client.get("/api/scans").json()["scans"]
    assert history[0]["github"]["source"] == "github_actions"
    assert len(manager.get_scan_history(rid)) == 1
    scanner.assert_not_called()


def test_sync_endpoints_require_authentication_and_csrf(scan_environment, scan_client):
    from fastapi.testclient import TestClient

    api, _, repositories, *_ = scan_environment
    with TestClient(api.app) as anonymous:
        assert anonymous.get("/api/github/status").status_code == 401
        assert anonymous.post("/api/github/sync").status_code == 401
    rid = repositories[0]["id"]
    assert scan_client.post(f"/api/repositories/{rid}/sync", headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert scan_client.post("/api/github/sync", headers={"X-CSRF-Token": "bad"}).status_code == 403


def test_invalid_repository_url_rejected_before_insert(scan_environment, scan_client):
    _, manager, *_ = scan_environment
    assert scan_client.post("/api/repositories", json={"repo_url": "https://example.com/wrong"}).status_code == 400
    assert len(manager.get_repositories()) == 2


def test_unconfigured_api_exposes_no_credentials(scan_environment, scan_client, monkeypatch):
    from repository import github_client
    monkeypatch.setattr(github_client, "ENV_PATH", github_client.ENV_PATH.parent / "missing-test-settings.env")
    for key in ("APP_ID", "INSTALLATION_ID", "PRIVATE_KEY_PATH"):
        monkeypatch.delenv("DEVSECOPS_GITHUB_" + key, raising=False)
    assert scan_client.get("/api/github/status").json() == {"configured": False, "authentication": "github_app"}
    response = scan_client.post("/api/github/sync")
    assert response.status_code == 200
    assert all(item["execution_status"] == "error" and item["policy_status"] is None for item in response.json()["results"])


def test_failed_run_is_visible_in_history_without_a_fake_score(scan_environment, scan_client, monkeypatch):
    api, _, repositories, *_ = scan_environment
    client = Client()
    client.content = b"invalid zip"
    monkeypatch.setattr(api.github_monitor, "GitHubClient", lambda: client)
    assert scan_client.post(f"/api/repositories/{repositories[0]['id']}/sync").status_code == 200
    history = scan_client.get('/api/scans').json()['scans']
    assert len(history) == 1
    row = history[0]
    assert row['report_available'] is False and row['execution_status'] == 'error'
    assert row['score'] is None and row['status'] is None and row['findings'] is None


def test_invalidated_previous_allow_is_not_duplicated_as_clean_history(scan_environment, scan_client, monkeypatch):
    from contextlib import closing
    from repository.database import get_connection
    api, _, repositories, *_ = scan_environment
    client = Client()
    monkeypatch.setattr(api.github_monitor, 'GitHubClient', lambda: client)
    rid = repositories[0]['id']
    scan_client.post(f'/api/repositories/{rid}/sync')
    with closing(get_connection()) as connection, connection:
        connection.execute("UPDATE github_imports SET metadata=json_remove(metadata,'$.validation_version')")
    client.content = b'invalid legacy report'
    scan_client.post(f'/api/repositories/{rid}/sync')
    rows = scan_client.get('/api/scans').json()['scans']
    assert len(rows) == 1 and rows[0]['status'] is None and rows[0]['report_available'] is False
