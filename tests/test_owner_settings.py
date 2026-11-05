"""Owner Settings contracts with temporary databases/keys and mocked GitHub HTTP only."""

import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import closing
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from test_auth import auth_environment, login
from test_github_monitor import Client
from repository import database, github_client, github_monitor, owner_settings


@pytest.fixture
def candidate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "test-only.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return {"owner": "new-owner", "app_id": "123", "installation_id": "456",
            "private_key_path": str(path), "workflow": "security-gate.yml"}


@pytest.fixture
def github_http(monkeypatch):
    state = {"calls": [], "owner": "new-owner", "fail": False, "permissions": True}

    def handler(request):
        state["calls"].append(request.url.path)
        if state["fail"]:
            return httpx.Response(403, text="private-response-body-secret")
        if request.url.path == "/app":
            return httpx.Response(200, json={"id": 123})
        if request.url.path == "/app/installations/456":
            return httpx.Response(200, json={"app_id": 123, "account": {"login": state["owner"]},
                "permissions": {"actions": "read", "contents": "read", "metadata": "read"} if state["permissions"] else {}})
        if request.url.path.endswith("/access_tokens"):
            assert json.loads(request.content) == {"permissions": {"contents": "read", "actions": "read"}}
            return httpx.Response(201, json={"token": "test-installation-token-secret"})
        assert request.url.path == "/installation/repositories"
        assert request.headers["Authorization"] == "Bearer test-installation-token-secret"
        return httpx.Response(200, json={"total_count": 2, "repositories": [{"name": "example"}]})

    original = github_client.GitHubClient.__init__

    def create(self, settings=None):
        original(self, settings=settings)
        self.client.close()
        self.client = httpx.Client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(github_client.GitHubClient, "__init__", create)
    return state


def test_environment_fallback_and_non_creating_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(github_client, "ENV_PATH", tmp_path / "missing.env")
    for key in github_client.GITHUB_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DEVSECOPS_GITHUB_OWNER", "env-owner")
    assert owner_settings.current()["DEVSECOPS_GITHUB_OWNER"] == "env-owner"
    assert not database.DATABASE_PATH.exists()
    database.initialize_database()
    assert owner_settings.read()["source"] == "environment"
    assert owner_settings.read()["settings"]["workflow"] == "security-gate-test.yml"


@pytest.mark.parametrize("role", [None, "viewer", "operator", "superuser"])
def test_settings_access_roles_and_csrf(auth_environment, candidate, github_http, role):
    with TestClient(auth_environment["api"].app) as client:
        headers = {}
        if role:
            _, headers = login(client, "admin" if role == "superuser" else role)
        for method, path in [("GET", "/api/owner-settings"), ("POST", "/api/owner-settings/test"), ("POST", "/api/owner-settings")]:
            response = client.request(method, path, json=candidate if method == "POST" else None, headers=headers)
            assert response.status_code == (200 if role == "superuser" else 401 if role is None else 403), response.text
        page = client.get("/dashboard/settings.html", follow_redirects=False)
        assert page.status_code == (200 if role == "superuser" else 303 if role is None else 403)
        if role == "superuser":
            for path in ("/api/owner-settings", "/api/owner-settings/test"):
                assert client.post(path, json=candidate).status_code == 403
                assert client.post(path, json=candidate, headers={"X-CSRF-Token": "forged"}).status_code == 403
        else:
            assert github_http["calls"] == []


def test_test_does_not_save_then_save_persists_and_preserves_history(auth_environment, candidate, github_http, monkeypatch):
    api = auth_environment["api"]
    manager = api.repository_manager
    scan_id = auth_environment["scan_id"]
    with TestClient(api.app) as client:
        _, headers = login(client)
        initial = client.get("/api/owner-settings").json()
        tested = client.post("/api/owner-settings/test", json=candidate, headers=headers)
        assert tested.status_code == 200 and tested.json()["repositories_accessible"] == 2
        assert client.get("/api/owner-settings").json() == initial
        saved = client.post("/api/owner-settings", json=candidate, headers=headers)
        assert saved.status_code == 200, saved.text
        assert len(github_http["calls"]) == 8  # Save verifies again; a previous Test is insufficient.
        assert saved.json()["source"] == "database" and saved.json()["settings"] == candidate
        monkeypatch.setenv("DEVSECOPS_GITHUB_OWNER", "ignored-env-owner")
        database.initialize_database()
        database.initialize_database()
        assert client.get("/api/owner-settings").json() == saved.json()
        assert manager.get_all_scans()[0]["id"] == scan_id
        assert len(auth_environment["service"].list_users()) == 3
        audit = client.get("/api/users/audit").json()["events"][0]
        assert audit["action"] == "owner_settings.updated"
        assert audit["actor_username"] == "admin" and audit["after"] == candidate
        assert audit["target_username"] == "Owner Settings"
        output = json.dumps([saved.json(), tested.json(), audit])
        assert "PRIVATE KEY" not in output and "test-installation-token-secret" not in output
        # An entirely fresh Python process reads the same saved values over Environment.
        process = subprocess.run(
            [sys.executable, "-c", "import json; from repository.owner_settings import current; print(json.dumps(current()))"],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "DEVSECOPS_DATABASE_PATH": str(database.DATABASE_PATH), "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert process.returncode == 0, process.stderr
        assert json.loads(process.stdout)["DEVSECOPS_GITHUB_OWNER"] == "new-owner"


@pytest.mark.parametrize("field,value", [
    ("owner", "https://github.com/new-owner"), ("owner", "-bad-owner"),
    ("app_id", "Iv1.client-id"), ("installation_id", "0"),
    ("workflow", "../security-gate.yml"), ("workflow", "security-gate.txt"),
    ("private_key_path", "relative.pem"), ("private_key_path", "C:\\missing-owner-settings-test.pem"),
])
def test_invalid_fields_never_save_or_contact_github(auth_environment, candidate, github_http, field, value):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        response = client.post("/api/owner-settings", json={**candidate, field: value}, headers=headers)
        assert response.status_code == 422
        assert field in response.json()["detail"]["fields"]
        assert client.get("/api/owner-settings").json()["source"] == "environment"
        assert not github_http["calls"]


def test_key_must_be_supported_private_key(candidate):
    from pathlib import Path
    path = Path(candidate["private_key_path"])
    for content in (b"not a key", b"-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"):
        path.write_bytes(content)
        with pytest.raises(owner_settings.SettingsValidationError) as error:
            owner_settings.validate(candidate)
        assert set(error.value.errors) == {"private_key_path"}
        assert "invalid\n" not in str(error.value.errors)


@pytest.mark.parametrize("failure", ["http", "owner", "permissions"])
def test_connection_failure_keeps_previous_values(auth_environment, candidate, github_http, failure, caplog):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        assert client.post("/api/owner-settings", json=candidate, headers=headers).status_code == 200
        old = client.get("/api/owner-settings").json()
        if failure == "http":
            github_http["fail"] = True
        elif failure == "owner":
            github_http["owner"] = "different-owner"
        else:
            github_http["permissions"] = False
        for path in ("/api/owner-settings/test", "/api/owner-settings"):
            failed = client.post(path, json=candidate, headers=headers)
            assert failed.status_code == 422
            assert "connection" in failed.json()["detail"]["fields"]
            assert "private-response-body-secret" not in failed.text + caplog.text
            assert "test-installation-token-secret" not in failed.text + caplog.text
        assert client.get("/api/owner-settings").json() == old


def test_new_owner_applies_to_urls_and_old_repo_sync_stops_without_fake_allow(auth_environment, candidate, github_http, monkeypatch):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        assert client.post("/api/owner-settings", json=candidate, headers=headers).status_code == 200
        assert client.post("/api/repositories", json={"repo_url": "https://github.com/TRM-MYOS/old-new"}, headers=headers).status_code == 400
        assert client.post("/api/repositories", json={"repo_url": "https://github.com/new-owner/example"}, headers=headers).status_code == 200
        network = Mock(side_effect=AssertionError("Old owner must not be contacted"))
        monkeypatch.setattr(github_monitor, "GitHubClient", network)
        rid = auth_environment["repository"]["id"]
        for payload in ({}, {"branch": "main"}):
            result = client.post(f"/api/repositories/{rid}/sync", json=payload, headers=headers).json()
            assert result["execution_status"] == "not_monitored" and result["policy_status"] is None
        old = next(r for r in client.get("/api/repositories").json()["repositories"] if r["id"] == rid)
        assert old["tracking"]["policy_status"] is None and old["tracking"]["branches"] == []
        assert client.get("/api/scans").json()["scans"][0]["status"] == "ALLOW"  # Historical evidence remains.
        network.assert_not_called()


def test_save_waits_for_active_sync_and_next_client_uses_new_snapshot(auth_environment, candidate):
    manager = auth_environment["api"].repository_manager
    rid = auth_environment["repository"]["id"]
    entered, release, saving = threading.Event(), threading.Event(), threading.Event()
    before = owner_settings.current()

    class SlowClient(Client):
        def get(self, path, params=None):
            entered.set()
            assert release.wait(timeout=10)
            assert owner_settings.current() == before
            return super().get(path, params)

    def save():
        saving.set()
        return owner_settings.save(candidate, auth_environment["users"]["superuser"]["id"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        sync = pool.submit(github_monitor.sync_all_branches, manager, rid, SlowClient())
        assert entered.wait(timeout=10)
        write = pool.submit(save)
        try:
            assert saving.wait(timeout=2)
            with pytest.raises(TimeoutError):
                write.result(timeout=0.1)
        finally:
            release.set()
        assert sync.result(timeout=10)["branches"][0]["policy_status"] == "ALLOW"
        assert write.result(timeout=10)["settings"] == candidate
    assert github_monitor.tracking(rid)["policy_status"] is None
    new_client = github_client.GitHubClient()
    try:
        assert new_client.settings["DEVSECOPS_GITHUB_OWNER"] == "new-owner"
        assert new_client.token is None
    finally:
        new_client.close()


def test_actor_is_rechecked_after_connection_verification(auth_environment, candidate, github_http, monkeypatch):
    service = auth_environment["service"]
    service.create_user("second-admin", "Test-second-admin-83!", "superuser")
    original = owner_settings.test_connection

    def revoke(values):
        result = original(values)
        service.update_user(auth_environment["users"]["superuser"]["id"], {"role": "viewer"})
        return result

    monkeypatch.setattr(owner_settings, "test_connection", revoke)
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        assert client.post("/api/owner-settings", json=candidate, headers=headers).status_code == 403
    with closing(database.get_connection()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM owner_settings").fetchone()[0] == 0


def test_workflow_uses_saved_snapshot_without_changing_central_trust(auth_environment, candidate):
    candidate = {**candidate, "owner": "TRM-MYOS"}
    owner_settings.save(candidate, auth_environment["users"]["superuser"]["id"])
    client = Client()
    original = client.get
    paths = []

    def get(path, params=None):
        paths.append(path)
        return original(path, params)

    client.get = get
    trusted = github_monitor.TRUSTED_WORKFLOW
    result = github_monitor.sync_all_branches(auth_environment["api"].repository_manager,
        auth_environment["repository"]["id"], client=client)
    assert result["branches"][0]["policy_status"] == "ALLOW"
    assert any("/workflows/security-gate.yml/runs" in path for path in paths)
    assert github_monitor.TRUSTED_WORKFLOW == trusted


def test_stale_round_from_another_worker_cannot_restore_current_allow(auth_environment, candidate):
    from repository.owner_settings import _snapshot
    rid = auth_environment["repository"]["id"]
    old = owner_settings.current()
    owner_settings.save({**candidate, "owner": "TRM-MYOS"}, auth_environment["users"]["superuser"]["id"])
    # Simulate another process finishing an older round after this process saved.
    token = _snapshot.set(old)
    try:
        github_monitor._store(rid, {"execution_status": "completed", "policy_status": "ALLOW"})
    finally:
        _snapshot.reset(token)
    result = github_monitor.tracking(rid)
    assert result["execution_status"] == "not_synced" and result["policy_status"] is None


def test_clients_pin_credentials_and_never_reuse_token_between_configurations(candidate):
    first = github_client.GitHubClient(settings={owner_settings.FIELDS[f]: v for f, v in candidate.items()})
    second = github_client.GitHubClient(settings={owner_settings.FIELDS[f]: v for f, v in {**candidate, "app_id": "999"}.items()})
    try:
        first.token = "old-test-only-token"
        assert first.settings["DEVSECOPS_GITHUB_APP_ID"] == "123"
        assert second.settings["DEVSECOPS_GITHUB_APP_ID"] == "999" and second.token is None
        assert first._token() == "old-test-only-token"
    finally:
        first.close()
        second.close()
