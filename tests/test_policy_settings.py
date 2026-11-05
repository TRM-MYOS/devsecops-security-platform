"""Signed policy publication and Runner evaluation without live HTTP or production keys."""
import base64
from contextlib import closing
import io
import json
import time
import subprocess
import sys
import os
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from test_auth import auth_environment, login
from repository import policy_settings, github_monitor
from security import policy, policy_source
from security.parser import build_summary, parse_reports
from security.scoring import calculate_score, calculate_grade


@pytest.fixture
def signed(auth_environment, tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "policy-test.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setenv("DEVSECOPS_POLICY_SIGNING_KEY_PATH", str(path))
    source = tmp_path / "policy-source.json"
    source.write_text(json.dumps({"url": "https://policy.example/policy/v1", "public_key": base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(), "maximum_age_seconds": 900, "required_from": int(time.time()) - 60}))
    monkeypatch.setattr(policy_source, "SOURCE_PATH", source)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return json.dumps(policy_settings.publication()).encode()
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://policy.example/policy/v1" and timeout == 10
            return Response()
    monkeypatch.setattr(policy_source, "build_opener", lambda *args: Opener())
    return auth_environment, key, source


@pytest.mark.parametrize("role", [None, "operator", "viewer", "superuser"])
def test_only_admin_can_set_global_threshold(auth_environment, role):
    with TestClient(auth_environment["api"].app) as client:
        csrf = {}
        if role:
            _, csrf = login(client, "admin" if role == "superuser" else role)
            assert client.get("/api/policy").status_code == 200
        response = client.patch("/api/policy", json={"minimum_score": 80}, headers=csrf)
        assert response.status_code == (200 if role == "superuser" else 401 if role is None else 403)
        if role == "superuser":
            assert response.json()["settings"]["activation"] == "setup_required"
            assert response.json()["central_file_minimum"] == 60
            assert client.patch("/api/policy", json={"minimum_score": 90}).status_code == 403


@pytest.mark.parametrize("value,expected", [(0,200),(100,200),(-1,422),(101,422),(True,422),(70.5,422),("80",422)])
def test_threshold_boundaries_and_persistence(auth_environment, value, expected):
    with TestClient(auth_environment["api"].app) as client:
        _, csrf = login(client)
        response = client.patch("/api/policy", json={"minimum_score": value}, headers=csrf)
        assert response.status_code == expected
        if expected == 200:
            settings = response.json()["settings"]
            auth_environment["database"].initialize_database()
            assert policy_settings.current()["version"] == settings["version"]
            assert policy_settings.current()["minimum_score"] == value
            fresh = subprocess.run([sys.executable,"-c","import json; from repository.policy_settings import current; print(json.dumps(current()))"],
                env={**os.environ,"DEVSECOPS_DATABASE_PATH":str(auth_environment['database'].DATABASE_PATH),"PYTHONDONTWRITEBYTECODE":"1"},
                capture_output=True,text=True,timeout=15)
            assert fresh.returncode == 0 and json.loads(fresh.stdout)["version"] == settings["version"]
            assert json.loads(fresh.stdout)["minimum_score"] == value
            old = auth_environment["api"].repository_manager.get_all_scans()[0]
            assert old["status"] == "ALLOW" and old["score"] == 100
            audit = auth_environment["service"].list_audit_events()[0]
            assert audit["action"] == "policy.updated" and "PRIVATE KEY" not in str(audit)


def test_real_publication_drives_runner_without_changing_scoring(signed):
    env, *_ = signed
    findings = [{"severity": "MEDIUM"}]
    score = calculate_score(findings)
    assert score == 85
    first = policy_settings.save(90, env["users"]["superuser"]["id"])
    decision = policy.evaluate_policy(findings, score)
    assert decision["status"] == "BLOCK" and decision["policy"]["version"] == first["version"]
    policy_settings.save(80, env["users"]["superuser"]["id"])
    assert policy.evaluate_policy(findings, score)["status"] == "ALLOW"
    for severity in ("HIGH", "CRITICAL"):
        assert policy.evaluate_policy([{"severity": severity}], 100)["status"] == "BLOCK"
    with TestClient(env["api"].app) as client:
        response = client.get("/policy/v1")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert "PRIVATE KEY" not in response.text and "private_key" not in response.text


@pytest.mark.parametrize("change", ["threshold", "signature", "expired", "future", "severity"])
def test_tampered_or_stale_policy_fails_closed(signed, change):
    _, key, _ = signed
    envelope = policy_settings.publication()
    if change == "threshold":
        envelope["payload"]["minimum_score"] = 0
    elif change == "signature":
        envelope["signature"] = base64.b64encode(b"invalid").decode()
    else:
        if change == "expired": envelope["payload"].update(issued_at=int(time.time())-1000, expires_at=int(time.time())-100)
        if change == "future": envelope["payload"].update(issued_at=int(time.time())+100, expires_at=int(time.time())+900)
        if change == "severity": envelope["payload"]["block_severities"] = []
        envelope["signature"] = base64.b64encode(key.sign(policy_source.canonical(envelope["payload"]))).decode()
    with pytest.raises(RuntimeError, match="Policy Failure"):
        policy_source.verify(envelope, policy_source.source_config())


def test_policy_download_failure_does_not_fall_back(signed, monkeypatch):
    def failure(*args): raise OSError("sensitive response must not escape")
    monkeypatch.setattr(policy_source, "build_opener", failure)
    with pytest.raises(RuntimeError, match="cannot obtain a verified") as error:
        policy.evaluate_policy([],100)
    assert "sensitive" not in str(error.value)


def test_source_identity_is_pinned_in_central_not_environment(signed, monkeypatch):
    _, _, path = signed
    monkeypatch.setenv("DEVSECOPS_POLICY_SOURCE_URL", "https://attacker.example")
    assert policy_source.source_config()["url"] == "https://policy.example/policy/v1"
    path.write_text('{"url":"http://insecure.example"}')
    with pytest.raises(RuntimeError, match="invalid trusted"):
        policy.evaluate_policy([],100)


def test_import_keeps_policy_version_and_verifies_historical_signature(signed, tmp_path):
    env, *_ = signed
    policy_settings.save(90, env["users"]["superuser"]["id"])
    files = {"bandit.json": {"results":[],"errors":[]}, "trivy.json": {"SchemaVersion":2,"ArtifactName":"target","ArtifactType":"filesystem","Results":[{"Target":"app.py","Secrets":[{"RuleID":"synthetic","Severity":"MEDIUM","Title":"Synthetic","StartLine":3}]}]}, "gitleaks.json":[]}
    for name, content in files.items(): (tmp_path/name).write_text(json.dumps(content))
    findings = parse_reports(*(tmp_path/name for name in files))
    score = calculate_score(findings)
    decision = policy.evaluate_policy(findings,score)
    files["security-summary.json"] = build_summary(findings,score,calculate_grade(score),decision)
    def archive():
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w") as z:
            for name, content in files.items(): z.writestr(name,json.dumps(content))
        return output.getvalue()
    when = time.time()
    result = github_monitor.read_reports(archive(),policy_time=when)
    assert result["status"] == "BLOCK" and result["policy"]["minimum_score"] == 90
    policy_settings.save(0, env["users"]["superuser"]["id"])
    assert github_monitor.read_reports(archive(),policy_time=when)["status"] == "BLOCK"
    files["security-summary.json"]["policy"]["minimum_score"] = 0
    with pytest.raises(RuntimeError,match="signature"):
        github_monitor.read_reports(archive(),policy_time=when)


def test_unsigned_report_after_activation_is_rejected(signed):
    from test_github_monitor import artifact
    with pytest.raises(RuntimeError,match="required signed policy"):
        github_monitor.read_reports(artifact(), policy_time=time.time())
    assert github_monitor.read_reports(artifact(),policy_time=1)["status"] == "ALLOW"


def test_policy_actor_revoked_after_middleware_cannot_save(auth_environment, monkeypatch):
    env = auth_environment
    env["service"].create_user("second-admin", "Test-password-83!", "superuser")
    original = policy_settings.save
    def revoked(minimum, actor_id):
        env["service"].update_user(actor_id,{"role":"viewer"})
        return original(minimum,actor_id)
    monkeypatch.setattr(policy_settings,"save",revoked)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client)
        assert client.patch("/api/policy",json={"minimum_score":0},headers=csrf).status_code==403
    with closing(env["database"].get_connection()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM policy_settings").fetchone()[0]==0


def test_signed_policy_report_import_marks_version_observed(signed, tmp_path, monkeypatch):
    from datetime import datetime, timezone, timedelta
    from test_github_monitor import Client
    env, *_ = signed
    requested = policy_settings.save(90, env["users"]["superuser"]["id"])
    files = {"bandit.json":{"results":[],"errors":[]},"trivy.json":{"SchemaVersion":2,"ArtifactName":"target","ArtifactType":"filesystem"},"gitleaks.json":[]}
    decision = policy.evaluate_policy([],100)
    files["security-summary.json"] = build_summary([],100,"A",decision)
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w") as archive:
        for name, value in files.items():archive.writestr(name,json.dumps(value))
    fake = Client()
    now = datetime.now(timezone.utc)
    fake.run.update(run_started_at=(now-timedelta(seconds=20)).isoformat(),updated_at=(now+timedelta(seconds=5)).isoformat())
    fake.artifacts[0]["created_at"] = now.isoformat()
    fake.content = output.getvalue()
    monkeypatch.setattr(github_monitor,"GitHubClient",lambda:fake)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client)
        result=client.post(f"/api/repositories/{env['repository']['id']}/sync",headers=csrf)
        assert result.status_code==200 and result.json()["branches"][0]["policy_status"]=="ALLOW"
        scan_id = result.json()["branches"][0]["scan_id"]
        detail=client.get(f"/api/scans/{scan_id}").json()["scan"]
        assert detail["policy"]["version"]==requested["version"] and detail["policy"]["minimum_score"]==90
        assert client.get("/api/policy").json()["settings"]["activation"]=="observed_in_report"
