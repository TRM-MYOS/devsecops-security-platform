"""Fail-closed parser, scanner timeout and process-restart regression coverage."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security.parser import parse_trivy
from security.policy import evaluate_policy
from security.scoring import calculate_score


def trivy_report(tmp_path, results=None):
    data = {"SchemaVersion": 2, "ArtifactName": "target", "ArtifactType": "filesystem"}
    if results is not None:
        data["Results"] = results
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_trivy_secret_blocks_without_leaking_match_or_code(tmp_path):
    path = trivy_report(tmp_path, [{"Target": "config.py", "Secrets": [{
        "RuleID": "test-secret", "Severity": "HIGH", "Title": "Synthetic secret",
        "StartLine": 3, "EndLine": 3, "Match": "test-only-sensitive-match",
        "Code": {"Lines": [{"Content": "test-only-sensitive-code"}]},
    }]}])
    findings = parse_trivy(path)
    assert len(findings) == 1
    assert findings[0]["category"] == "SECRET" and findings[0]["line"] == 3
    assert findings[0]["file"] == "config.py"
    assert "test-only-sensitive" not in json.dumps(findings)
    assert evaluate_policy(findings, calculate_score(findings))["status"] == "BLOCK"


@pytest.mark.parametrize("results", [None, [], [{"Target": "config.py", "Secrets": []}]])
def test_clean_trivy_reports_allow(tmp_path, results):
    findings = parse_trivy(trivy_report(tmp_path, results))
    assert findings == []
    assert evaluate_policy(findings, calculate_score(findings))["status"] == "ALLOW"


@pytest.mark.parametrize("secret", [None, {}, {"RuleID": "x", "Severity": "INVALID"},
    {"RuleID": "x", "Severity": "HIGH", "StartLine": True},
    {"RuleID": "x", "Severity": "HIGH", "StartLine": -1},
    {"RuleID": "x", "Severity": "HIGH", "StartLine": 9, "EndLine": 3},
    {"RuleID": "x", "Severity": "HIGH", "Title": []},
])
def test_malformed_trivy_secret_fails_closed(tmp_path, secret):
    with pytest.raises(SystemExit, match="Report Validation Failure: Trivy"):
        parse_trivy(trivy_report(tmp_path, [{"Target": "config.py", "Secrets": [secret]}]))


def test_optional_secret_location_and_title_do_not_drop_finding(tmp_path):
    findings = parse_trivy(trivy_report(tmp_path, [{"Target": "config.py", "Secrets": [{"RuleID": "x", "Severity": "HIGH"}]}]))
    assert len(findings) == 1 and findings[0]["line"] is None


def test_trivy_secrets_and_vulnerabilities_are_both_preserved(tmp_path):
    findings = parse_trivy(trivy_report(tmp_path, [{"Target": "requirements.txt",
        "Secrets": [{"RuleID": "x", "Severity": "HIGH"}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-test", "Severity": "MEDIUM"}],
    }]))
    assert [item["category"] for item in findings] == ["SECRET", "SCA"]
    assert calculate_score(findings) == 60


def test_scanner_timeout_terminates_real_process(monkeypatch):
    from scanner.security_scanner import run_command
    monkeypatch.setenv("DEVSECOPS_SCANNER_TIMEOUT_SECONDS", "1")
    with pytest.raises(RuntimeError, match="timed out after 1 seconds"):
        run_command([sys.executable, "-c", "import time; time.sleep(30)"])


@pytest.mark.parametrize("value", ["0", "-1", "bad"])
def test_invalid_timeout_fails_before_scanner_starts(monkeypatch, value):
    from scanner.security_scanner import run_command
    monkeypatch.setenv("DEVSECOPS_SCANNER_TIMEOUT_SECONDS", value)
    with pytest.raises(RuntimeError, match="positive integer"):
        run_command([sys.executable, "-c", "raise AssertionError('must not run')"])


def test_scanner_failure_removes_stale_summary(tmp_path, monkeypatch):
    from scanner import security_scanner as scanner
    target = tmp_path / "target"
    target.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "security-summary.json").write_text('{"status":"ALLOW"}')
    monkeypatch.setattr(scanner, "run_bandit", lambda *args: (_ for _ in ()).throw(RuntimeError("Scanner Failure: timed out")))
    with pytest.raises(RuntimeError):
        scanner.run_security_scan(target, reports)
    assert not (reports / "security-summary.json").exists()


def test_restart_preserves_accounts_sessions_repositories_and_findings(tmp_path):
    """Two fresh Python processes use one isolated persistent database, no live GitHub."""
    environment = {**os.environ, "DEVSECOPS_DATABASE_PATH": str(tmp_path / "restart.db"),
        "DEVSECOPS_ENV": "development", "DEVSECOPS_COOKIE_SECURE": "false",
        "DEVSECOPS_GITHUB_POLL_ENABLED": "false", "PYTHONDONTWRITEBYTECODE": "1"}
    setup = """
import json
from repository.repository_manager import RepositoryManager
from auth.service import bootstrap_superuser,create_session
m=RepositoryManager()
u=bootstrap_superuser('restart-admin','Restart-test-only-password!')
r=m.add_repository('https://github.com/TRM-MYOS/restart-test')
m.save_scan(r['id'],'2026-10-19T00:00:00Z',75,'C','BLOCK','Synthetic finding',[{'scanner':'Trivy','severity':'HIGH','file':'app.py','line':3}])
print(json.dumps(create_session(u['id'])))
"""
    first = subprocess.run([sys.executable, "-B", "-c", setup], env=environment, capture_output=True, text=True, timeout=30)
    assert first.returncode == 0, first.stderr
    session = json.loads(first.stdout)
    environment["TEST_ONLY_SESSION"] = session["token"]
    verify = """
import os
from fastapi.testclient import TestClient
from api.app import app
with TestClient(app) as c:
 c.cookies.set('devsecops_session',os.environ['TEST_ONLY_SESSION'])
 assert c.get('/api/auth/me').json()['user']['username']=='restart-admin'
 assert len(c.get('/api/repositories').json()['repositories'])==1
 scans=c.get('/api/scans').json()['scans']
 assert len(scans)==1 and scans[0]['status']=='BLOCK'
 assert c.get('/api/scans/'+str(scans[0]['id'])+'/findings').json()['findings'][0]['line']==3
print('restart persistence passed')
"""
    second = subprocess.run([sys.executable, "-B", "-c", verify], env=environment, capture_output=True, text=True, timeout=30)
    assert second.returncode == 0, second.stderr
    assert "restart persistence passed" in second.stdout
