"""Outbound Central publication through a scoped App token; no live GitHub writes."""

import base64
from contextlib import closing
import copy
import hashlib
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
        self.deny = self.conflict = self.https_source = False
        self.timeout_after_write = self.reject_write = self.hide_write = False
        self.malformed = False
        self.head_reads = 0
        self.change_on_second_head = False
        self.history = {}
        self.on_write = None

    def handle(self, request):
        self.requests.append(request)
        body = json.loads(request.content) if request.content else None
        if request.url.path.endswith("/access_tokens"):
            assert body == {"repositories": ["devsecops-security-platform"],
                            "permissions": {"contents": "write"}}
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
            self.head_reads += 1
            if self.change_on_second_head and self.head_reads == 2:
                self.main = "d" * 40
            return httpx.Response(200, json={"commit": {"sha": self.main}})
        if path == "contents/security-policy-source.json":
            return httpx.Response(200, json={"type": "file"}) if self.https_source else httpx.Response(404)
        if path == f"contents/{publisher.POLICY_PATH}":
            if request.method == "GET":
                ref = request.url.params["ref"]
                config = self.contents["main"] if ref == self.main else self.history[ref]
                raw = yaml.safe_dump(config).encode()
                if self.malformed:
                    raw = b"policy: [invalid"
                return httpx.Response(200, json={"type": "file", "encoding": "base64", "size": len(raw),
                    "sha": hashlib.sha1(raw).hexdigest(), "content": base64.b64encode(raw).decode()})
            assert request.method == "PUT" and body["branch"] == "main"
            assert body["sha"] == hashlib.sha1(yaml.safe_dump(self.contents["main"]).encode()).hexdigest()
            if self.conflict:
                return httpx.Response(409)
            if self.reject_write:
                return httpx.Response(403, json={"message": "Protected branch private diagnostic"})
            if not self.hide_write:
                self.history[self.main] = copy.deepcopy(self.contents["main"])
                self.contents["main"] = yaml.safe_load(base64.b64decode(body["content"]))
                self.main = hashlib.sha1(body["content"].encode()).hexdigest()
            if self.timeout_after_write:
                self.timeout_after_write = False
                raise httpx.ReadTimeout("Sensitive diagnostic", request=request)
            return httpx.Response(200, json={"commit": {"sha": self.main}})
        raise AssertionError((request.method, str(request.url)))


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


def test_apply_is_policy_only_idempotent_and_drives_real_report_without_pr(central, tmp_path, monkeypatch):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    first = publisher.publish(desired["version"], actor)
    assert first["state"] == "applied" and fake.contents["main"]["policy"]["minimum_score"] == 90
    assert not fake.pulls and not fake.refs
    assert publisher.publish(desired["version"], actor)["commit_sha"] == first["commit_sha"]
    writes = [r for r in fake.requests if r.method == "PUT"]
    assert len(writes) == 1 and writes[0].url.path.endswith("/contents/security-policy.yaml")
    assert publisher.check(desired["version"], actor)["state"] == "applied"
    assert policy_settings.status()["activation"] == "published_awaiting_report"
    central_file = tmp_path / "central-policy.yaml"
    central_file.write_text(yaml.safe_dump(fake.contents["main"]))
    monkeypatch.setattr(policy, "CONFIG_PATH", central_file)
    result = policy.evaluate_policy([{"severity": "MEDIUM"}], 85)
    assert result["status"] == "BLOCK" and result["policy"]["version"] == desired["version"]
    assert result["policy"]["minimum_score"] == 90
    assert policy.evaluate_policy([{"severity": "HIGH"}], 100)["status"] == "BLOCK"
    assert policy.evaluate_policy([{"severity": "CRITICAL"}], 100)["status"] == "BLOCK"
    # Run the real report CLI in a new process against the applied YAML, then import
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
    fake.contents["main"]["policy"]["version"] = "superseding-policy"
    fake.main = "f" * 40
    publisher.check(desired["version"], actor)
    assert policy_settings.status()["activation"] == "publication_superseded"


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


@pytest.mark.parametrize("failure", ["deny", "conflict", "reject_write", "https_source", "malformed", "change_on_second_head"])
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


@pytest.mark.parametrize("recover_with", ["retry", "check"])
def test_uncertain_write_reconciles_without_duplicate_and_survives_restart(central, recover_with):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    fake.timeout_after_write = True
    with pytest.raises(publisher.PublicationError):
        publisher.publish(desired["version"], actor)
    assert fake.contents["main"]["policy"]["version"] == desired["version"]
    recover = publisher.publish if recover_with == "retry" else publisher.check
    assert recover(desired["version"], actor)["state"] == "applied"
    assert len([r for r in fake.requests if r.method == "PUT"]) == 1
    assert not fake.pulls
    import os
    result = subprocess.run([sys.executable, "-B", "-c", "import json,sys;from repository.policy_publisher import read;print(json.dumps(read(sys.argv[1])))", desired["version"]],
        env={**os.environ, "DEVSECOPS_DATABASE_PATH": str(env["database"].DATABASE_PATH)}, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and json.loads(result.stdout)["state"] == "applied"


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


def test_success_response_without_matching_main_is_not_reported_as_applied(central):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    fake.hide_write = True
    with pytest.raises(publisher.PublicationError, match="does not match"):
        publisher.publish(desired["version"], actor)
    assert policy_settings.status()["activation"] == "publish_failed"
    assert fake.contents["main"]["policy"]["minimum_score"] == 60


@pytest.mark.parametrize("minimum", [0, 100])
def test_boundary_thresholds_preserve_severity_rules_and_detect_supersession(central, minimum):
    fake, env = central
    actor = env["users"]["superuser"]["id"]
    before = copy.deepcopy(fake.contents["main"])
    desired = saved(env, minimum)
    publisher.publish(desired["version"], actor)
    expected = copy.deepcopy(before)
    expected["policy"].update(minimum_score=minimum, version=desired["version"])
    assert fake.contents["main"] == expected
    fake.contents["main"]["policy"].update(minimum_score=60, version="another-version")
    fake.main = "e" * 40
    assert publisher.check(desired["version"], actor)["state"] == "superseded"
    assert policy_settings.status()["activation"] == "publication_superseded"


def test_legacy_pr_record_can_apply_without_creating_or_merging_pr(central):
    fake, env = central
    desired = saved(env)
    actor = env["users"]["superuser"]["id"]
    legacy = {"version": desired["version"], "minimum_score": 90, "base_sha": "0" * 40,
              "branch": "dashboard-policy/old", "state": "awaiting_merge", "pr_number": 3,
              "pr_url": f"https://github.com/{publisher.CENTRAL_REPOSITORY}/pull/3"}
    publisher._persist(actor, legacy)
    result = publisher.publish(desired["version"], actor)
    assert result["state"] == "applied" and result["method"] == "direct"
    assert result["pr_number"] == 3
    assert not fake.pulls and not fake.refs


@pytest.mark.parametrize("version", [None, True, 0, "", "has spaces", "x" * 101])
def test_malformed_explicit_policy_version_fails_closed(version):
    config = {"policy": {"minimum_score": 60, "version": version},
              "severity": {"high": "BLOCK", "critical": "BLOCK"}}
    with pytest.raises(RuntimeError, match="invalid policy version"):
        policy.validate_policy_config(config)
