"""Actual loopback HTTPS and a separate Gate process; scanner outputs are fixtures.

These tests do not run GitHub Actions or contact live repositories. All database,
TLS certificate, signing key and report files belong to pytest's temporary path.
"""

import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from test_auth import auth_environment, login


@pytest.fixture
def https_policy(auth_environment, tmp_path, monkeypatch):
    signing = ed25519.Ed25519PrivateKey.generate()
    signing_path = tmp_path / "policy-only-test.pem"
    signing_path.write_bytes(signing.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    monkeypatch.setenv("DEVSECOPS_POLICY_SIGNING_KEY_PATH", str(signing_path))

    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False).sign(tls_key, hashes.SHA256()))
    cert_path, tls_path = tmp_path / "localhost.crt", tmp_path / "tls-test.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    tls_path.write_bytes(tls_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        port = listener.getsockname()[1]
        url = f"https://127.0.0.1:{port}"
        config = {
            "url": f"{url}/policy/v1",
            "public_key": base64.b64encode(signing.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )).decode(),
            "maximum_age_seconds": 900,
            "required_from": int(time.time()) - 60,
        }
        source = tmp_path / "trusted-source.json"
        source.write_text(json.dumps(config), encoding="utf-8")
        from security import policy_source
        monkeypatch.setattr(policy_source, "SOURCE_PATH", source)
        server = uvicorn.Server(uvicorn.Config(
            auth_environment["api"].app, host="127.0.0.1", port=port,
            ssl_keyfile=str(tls_path), ssl_certfile=str(cert_path),
            lifespan="off", log_level="error", access_log=False,
        ))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                if not thread.is_alive():
                    pytest.fail("Temporary HTTPS server failed to start")
                time.sleep(0.02)
            assert server.started
            with httpx.Client(
                base_url=url, verify=ssl.create_default_context(cafile=str(cert_path)),
                trust_env=False, timeout=5,
            ) as client:
                _, csrf = login(client)
                yield client, csrf, source, cert_path
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "Temporary HTTPS server did not stop"


# Test-only scanner fixtures keep the real CLI, parser, scoring and policy flow.
GATE_PROCESS = r'''
import json, sys
from pathlib import Path
from security import policy_source
from scanner import security_scanner as scanner
policy_source.SOURCE_PATH = Path(sys.argv[1])
scenario, target, reports = sys.argv[2:]
files = {
    "bandit": {"results": [], "errors": []},
    "trivy": {"SchemaVersion": 2, "ArtifactName": "target", "ArtifactType": "filesystem", "Results": []},
    "gitleaks": [],
}
if scenario in ("medium", "high"):
    files["trivy"]["Results"] = [{"Target": "app.py", "Secrets": [{
        "RuleID": "fixture-secret", "Severity": scenario.upper(),
        "Title": "Synthetic test finding", "StartLine": 3,
    }]}]
def stub(name):
    def run(target, path):
        if not (scenario == "missing-report" and name == "trivy"):
            path.write_text("{" if scenario == "corrupt-report" and name == "trivy"
                            else json.dumps(files[name]), encoding="utf-8")
        return {"returncode": 2 if scenario == "scanner-failure" and name == "bandit" else 0,
                "stdout": "", "stderr": "Synthetic scanner failure" if scenario == "scanner-failure" else ""}
    return run
scanner.run_bandit, scanner.run_trivy, scanner.run_gitleaks = (stub(n) for n in files)
scanner.main([target, reports])
'''


def run_gate(tmp_path, connection, scenario, name):
    _, _, source, certificate = connection
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    reports = tmp_path / name
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                   "SSL_CERT_FILE": str(certificate), "NO_PROXY": "127.0.0.1,localhost"}
    result = subprocess.run(
        [sys.executable, "-B", "-c", GATE_PROCESS, str(source), scenario, str(target), str(reports)],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        capture_output=True, text=True, timeout=20,
    )
    summary = reports / "security-summary.json"
    return result, json.loads(summary.read_text(encoding="utf-8")) if summary.exists() else None


def test_dashboard_threshold_reaches_separate_gate_over_verified_https(https_policy, tmp_path):
    client, csrf, _, _ = https_policy
    saved = client.patch("/api/policy", json={"minimum_score": 90}, headers=csrf)
    assert saved.status_code == 200
    first = saved.json()["settings"]
    result, blocked = run_gate(tmp_path, https_policy, "medium", "blocked")
    assert result.returncode != 0 and blocked["status"] == "BLOCK"
    assert blocked["score"] == 85 and blocked["policy"]["minimum_score"] == 90
    assert blocked["policy"]["version"] == first["version"]
    assert blocked["policy"]["source"] == "signed-https"

    saved = client.patch("/api/policy", json={"minimum_score": 80}, headers=csrf)
    assert saved.status_code == 200
    result, allowed = run_gate(tmp_path, https_policy, "medium", "allowed")
    assert result.returncode == 0 and allowed["status"] == "ALLOW", result.stderr
    assert allowed["score"] == 85 and allowed["policy"]["minimum_score"] == 80
    assert allowed["policy"]["version"] == saved.json()["settings"]["version"]
    assert allowed["policy"]["version"] != blocked["policy"]["version"]
    assert json.loads((tmp_path / "blocked/security-summary.json").read_text())["policy"] == blocked["policy"]

    assert client.patch("/api/policy", json={"minimum_score": 0}, headers=csrf).status_code == 200
    result, high = run_gate(tmp_path, https_policy, "high", "high")
    assert result.returncode != 0 and high["status"] == "BLOCK"
    assert high["policy"]["minimum_score"] == 0
    assert client.patch("/api/policy", json={"minimum_score": 100}, headers=csrf).status_code == 200
    result, clean = run_gate(tmp_path, https_policy, "clean", "clean")
    assert result.returncode == 0 and clean["score"] == 100 and clean["status"] == "ALLOW"


@pytest.mark.parametrize("failure", ["scanner-failure", "missing-report", "corrupt-report", "policy-failure"])
def test_separate_gate_failure_never_writes_allow(https_policy, tmp_path, failure):
    client, csrf, source, _ = https_policy
    assert client.patch("/api/policy", json={"minimum_score": 0}, headers=csrf).status_code == 200
    if failure == "policy-failure":
        config = json.loads(source.read_text())
        config["url"] += "/missing"
        source.write_text(json.dumps(config))
    result, summary = run_gate(tmp_path, https_policy, failure, "failure")
    assert result.returncode != 0
    assert summary is None, "An unsuccessful Gate must not publish an ALLOW summary"
    assert "Status   : ALLOW" not in result.stdout
