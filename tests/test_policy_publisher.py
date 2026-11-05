"""Outbound Central publication through a scoped App token; no live GitHub writes."""

import base64
from contextlib import closing
import json
import io
import subprocess
import sys
import zipfile

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from repository import policy_publisher as publisher, policy_settings
from security import policy, policy_source
from test_auth import auth_environment, login


class Central:
    def __init__(self):
        self.main = "a" * 40
        self.contents = {"main": {"policy": {"minimum_score": 60}, "severity": {
            "critical": "BLOCK", "high": "BLOCK", "medium": "WARN", "low": "ALLOW"}}}
        self.refs, self.pulls, self.requests = {}, [], []
        self.deny = self.conflict = self.extra_file = self.https_source = False
        self.timeout_after_pr = False
        self.on_write = None

    def handle(self, request):
        self.requests.append(request)
        body = json.loads(request.content) if request.content else None
        if request.url.path.endswith("/access_tokens"):
            assert body == {"repositories": ["devsecops-security-platform"],
                            "permissions": {"contents": "write", "pull_requests": "write"}}
            if self.deny:
                return httpx.Response(403, json={"message": "Private diagnostics must not escape"})
            return httpx.Response(201, json={"token": "policy-test-only-token", "permissions": body["permissions"]})
        assert request.headers["Authorization"] == "Bearer policy-test-only-token"
        prefix = f"/repos/{publisher.CENTRAL_REPOSITORY}/"
        assert request.url.path.startswith(prefix)
        path = request.url.path[len(prefix):]
        if request.method != "GET" and self.on_write:
            callback, self.on_write = self.on_write, None
            callback()
        if path == "branches/main":
            return httpx.Response(200, json={"commit": {"sha": self.main}})
        if path == "contents/security-policy-source.json":
            return httpx.Response(200, json={"type": "file"}) if self.https_source else httpx.Response(404)
        if path == f"contents/{publisher.POLICY_PATH}":
            if request.method == "GET":
                ref = request.url.params["ref"]
                config = self.contents["main"] if ref == self.main else self.contents[ref]
                raw = yaml.safe_dump(config).encode()
                return httpx.Response(200, json={"type": "file", "encoding": "base64", "size": len(raw),
                    "sha": "b" * 40, "content": base64.b64encode(raw).decode()})
            assert request.method == "PUT" and body["branch"].startswith("dashboard-policy/")
            assert body["sha"] == "b" * 40
            if self.conflict:
                return httpx.Response(409)
            self.contents[body["branch"]] = yaml.safe_load(base64.b64decode(body["content"]))
            self.refs[body["branch"]] = "c" * 40
            return httpx.Response(200, json={"commit": {"sha": "c" * 40}})
        if path.startswith("git/ref/heads/"):
            branch = path.removeprefix("git/ref/heads/")
            return httpx.Response(200, json={"object": {"sha": self.refs[branch]}}) if branch in self.refs else httpx.Response(404)
        if path == "git/refs":
            branch = body["ref"].removeprefix("refs/heads/")
            assert body["sha"] == self.main
            self.refs[branch] = self.main
            self.contents[branch] = json.loads(json.dumps(self.contents["main"]))
            return httpx.Response(201, json={"ref": body["ref"]})
        if path.startswith("compare/"):
            return httpx.Response(200, json={"merge_base_commit": {"sha": self.main}, "files": [
                {"filename": publisher.POLICY_PATH, "status": "modified"},
            ] + ([{"filename": "scanner/security_scanner.py", "status": "modified"}] if self.extra_file else [])})
        if path == "pulls":
            if request.method == "GET":
                branch = request.url.params["head"].split(":", 1)[1]
                return httpx.Response(200, json=[p for p in self.pulls if p["head"]["ref"] == branch])
            assert body["base"] == "main" and body["maintainer_can_modify"] is False
            pull = {"number": len(self.pulls) + 1, "state": "open", "merged_at": None,
                    "head": {"ref": body["head"], "repo": {"full_name": publisher.CENTRAL_REPOSITORY}},
                    "base": {"ref": "main"}}
            self.pulls.append(pull)
            if self.timeout_after_pr:
                self.timeout_after_pr = False
                raise httpx.ReadTimeout("Sensitive diagnostic", request=request)
            return httpx.Response(201, json=pull)
        raise AssertionError((request.method, str(request.url)))

    def merge(self):
        pull = self.pulls[-1]
        pull.update(state="closed", merged_at="2026-11-05T00:00:00Z")
        self.contents["main"] = self.contents[pull["head"]["ref"]]
        self.main = "c" * 40


@pytest.fixture
def central(auth_environment, monkeypatch, tmp_path):
    fake = Central()
    real = publisher.PolicyGitHubClient
    def factory():
        client = real(settings={"DEVSECOPS_GITHUB_APP_ID": "1", "DEVSECOPS_GITHUB_INSTALLATION_ID": "2",
                                "DEVSECOPS_GITHUB_PRIVATE_KEY_PATH": str(tmp_path / "not-read.pem")})
        client.client.close()
        client._app_jwt = lambda: "app-test-only-jwt"
        client.client = httpx.Client(transport=httpx.MockTransport(fake.handle), follow_redirects=False)
        return client
    monkeypatch.setattr(publisher, "PolicyGitHubClient", factory)
    monkeypatch.setattr(policy_source, "SOURCE_PATH", tmp_path / "no-https-source.json")
    return fake, auth_environment


def saved(env, minimum=90):
    return policy_settings.save(minimum, env["users"]["superuser"]["id"])


def test_publish_is_policy_only_idempotent_and_applies_to_real_evaluator_after_merge(central, tmp_path, monkeypatch):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    first = publisher.publish(desired["version"], actor)
    assert first["state"] == "awaiting_merge" and fake.contents["main"]["policy"]["minimum_score"] == 60
    assert len(fake.pulls) == 1
    assert publisher.publish(desired["version"], actor)["pr_number"] == first["pr_number"]
    assert len(fake.pulls) == 1
    fake.merge()
    assert publisher.check(desired["version"], actor)["state"] == "merged"
    assert policy_settings.status()["activation"] == "published_awaiting_report"
    central_file = tmp_path / "central-policy.yaml"
    central_file.write_text(yaml.safe_dump(fake.contents["main"]))
    monkeypatch.setattr(policy, "CONFIG_PATH", central_file)
    result = policy.evaluate_policy([{"severity": "MEDIUM"}], 85)
    assert result["status"] == "BLOCK" and result["policy"]["version"] == desired["version"]
    assert result["policy"]["minimum_score"] == 90
    assert policy.evaluate_policy([{"severity": "HIGH"}], 100)["status"] == "BLOCK"
    assert policy.evaluate_policy([{"severity": "CRITICAL"}], 100)["status"] == "BLOCK"
    # Run the real report CLI in a new process against the merged YAML, then import
    # that report through the existing provenance-checked monitoring path.
    reports = tmp_path / "reports"
    reports.mkdir()
    files = {"bandit.json": {"results": [], "errors": []}, "gitleaks.json": [],
             "trivy.json": {"SchemaVersion": 2, "ArtifactName": "target", "ArtifactType": "filesystem", "Results": [{
                 "Target": "app.py", "Secrets": [{"RuleID": "fixture", "Severity": "MEDIUM", "Title": "Synthetic", "StartLine": 3}]}]}}
    for name, data in files.items():
        (reports / name).write_text(json.dumps(data))
    run = subprocess.run([sys.executable, "-B", "-c",
        "import sys;from pathlib import Path;from security import policy;policy.CONFIG_PATH=Path(sys.argv[1]);from security.parser import main;main(sys.argv[2])",
        str(central_file), str(reports)], capture_output=True, text=True, timeout=15)
    assert run.returncode == 1
    summary = json.loads((reports / "security-summary.json").read_text())
    assert summary["score"] == 85 and summary["policy"]["version"] == desired["version"]
    from test_github_monitor import Client
    from repository import github_monitor
    remote = Client()
    remote.run["conclusion"] = "failure"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        for path in reports.iterdir():
            output.writestr(path.name, path.read_bytes())
    remote.content = archive.getvalue()
    imported = github_monitor.sync_repository(env["api"].repository_manager, env["repository"]["id"], client=remote)
    assert imported["policy_status"] == "BLOCK"
    assert policy_settings.status()["activation"] == "observed_in_report"
    old = env["api"].repository_manager.get_scan(env["scan_id"])
    assert old["score"] == 100 and old["status"] == "ALLOW"
    assert "policy-test-only-token" not in str(env["service"].list_audit_events())


@pytest.mark.parametrize("role", [None, "viewer", "operator", "superuser"])
def test_publication_routes_require_admin_csrf_and_saved_version(central, role):
    fake, env = central
    version = saved(env)["version"]
    with TestClient(env["api"].app) as client:
        headers = login(client, "admin" if role == "superuser" else role)[1] if role else {}
        for path in ("/api/policy/publish", "/api/policy/publication/check"):
            response = client.post(path, json={"version": version}, headers=headers)
            assert response.status_code == (200 if role == "superuser" else 401 if role is None else 403)
        if role == "superuser":
            assert client.post("/api/policy/publish", json={"version": version}).status_code == 403
            assert client.post("/api/policy/publish", json={"version": version, "repository": "attacker/repo"}, headers=headers).status_code == 422
        else:
            assert not fake.requests


@pytest.mark.parametrize("failure", ["deny", "conflict", "extra_file", "https_source"])
def test_failure_leaves_main_unchanged_and_never_marks_published(central, failure):
    fake, env = central
    setattr(fake, failure, True)
    desired = saved(env)
    with pytest.raises(publisher.PublicationError):
        publisher.publish(desired["version"], env["users"]["superuser"]["id"])
    assert not fake.pulls and fake.contents["main"]["policy"]["minimum_score"] == 60
    status = policy_settings.status()
    assert status["activation"] == "publish_failed" and not status["runner_observed"]
    assert "Private diagnostics" not in str(status)


def test_uncertain_pr_response_reconciles_without_duplicate_and_survives_restart(central):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    fake.timeout_after_pr = True
    with pytest.raises(publisher.PublicationError):
        publisher.publish(desired["version"], actor)
    assert len(fake.pulls) == 1
    assert publisher.publish(desired["version"], actor)["state"] == "awaiting_merge"
    assert len(fake.pulls) == 1
    import os
    result = subprocess.run([sys.executable, "-B", "-c", "import json,sys;from repository.policy_publisher import read;print(json.dumps(read(sys.argv[1])))", desired["version"]],
        env={**os.environ, "DEVSECOPS_DATABASE_PATH": str(env["database"].DATABASE_PATH)}, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and json.loads(result.stdout)["state"] == "awaiting_merge"


def test_stale_version_and_revoked_administrator_cannot_publish(central):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    saved(env, 80)
    with pytest.raises(publisher.PublicationError, match="changed"):
        publisher.publish(desired["version"], actor)
    assert not fake.requests
    desired = saved(env)
    original = publisher._mutate
    def revoke(*args, **kwargs):
        with closing(env["database"].get_connection()) as connection, connection:
            connection.execute("UPDATE users SET role='viewer' WHERE id=?", (actor,))
        return original(*args, **kwargs)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(publisher, "_mutate", revoke)
        with pytest.raises(PermissionError):
            publisher.publish(desired["version"], actor)
    assert not fake.refs and not fake.pulls


def test_existing_pr_cannot_hide_additional_file_changes(central):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    publisher.publish(desired["version"], actor)
    fake.extra_file = True
    with pytest.raises(publisher.PublicationError, match="only Central"):
        publisher.publish(desired["version"], actor)
    assert len(fake.pulls) == 1 and fake.contents["main"]["policy"]["minimum_score"] == 60


@pytest.mark.parametrize("version", [None, True, 0, "", "has spaces", "x" * 101])
def test_malformed_explicit_policy_version_fails_closed(version):
    config = {"policy": {"minimum_score": 60, "version": version},
              "severity": {"high": "BLOCK", "critical": "BLOCK"}}
    with pytest.raises(RuntimeError, match="invalid policy version"):
        policy.validate_policy_config(config)
