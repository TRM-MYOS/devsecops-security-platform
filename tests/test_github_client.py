"""Signing and download safety with a local HTTP transport; no live GitHub calls."""

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from repository.github_client import GitHubClient, GitHubError


def test_configuration_reads_local_env_without_launcher(tmp_path, monkeypatch):
    from repository import github_client
    settings = tmp_path / ".env"
    settings.write_text(
        '\ufeffDEVSECOPS_GITHUB_APP_ID=123\n'
        'DEVSECOPS_GITHUB_INSTALLATION_ID="456"\n'
        "DEVSECOPS_GITHUB_PRIVATE_KEY_PATH='C:\\secure\\key.pem'\n"
        'DEVSECOPS_GITHUB_WORKFLOW=security-gate-test.yml\n'
        'UNRELATED_VALUE=ignored\n', encoding="utf-8",
    )
    monkeypatch.setattr(github_client, "ENV_PATH", settings)
    for key in github_client.GITHUB_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path.parent)
    assert github_client.configured()
    assert github_client.configuration()["DEVSECOPS_GITHUB_INSTALLATION_ID"] == "456"
    assert "UNRELATED_VALUE" not in github_client.configuration()
    assert "DEVSECOPS_GITHUB_APP_ID" not in __import__('os').environ
    monkeypatch.setenv("DEVSECOPS_GITHUB_APP_ID", "789")
    assert github_client.configuration()["DEVSECOPS_GITHUB_APP_ID"] == "789"


def test_missing_env_fails_closed(tmp_path, monkeypatch):
    from repository import github_client
    monkeypatch.setattr(github_client, "ENV_PATH", tmp_path / "missing.env")
    for key in github_client.GITHUB_KEYS:
        monkeypatch.delenv(key, raising=False)
    assert not github_client.configured()


@pytest.fixture
def client(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "app.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setenv("DEVSECOPS_GITHUB_APP_ID", "123")
    monkeypatch.setenv("DEVSECOPS_GITHUB_INSTALLATION_ID", "456")
    monkeypatch.setenv("DEVSECOPS_GITHUB_PRIVATE_KEY_PATH", str(path))
    client = GitHubClient()
    client.client.close()
    yield client, key
    client.close()


def test_app_signing_and_no_token_forwarding(client):
    client, key = client
    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            claims = jwt.decode(request.headers["Authorization"].split()[1], key.public_key(), algorithms=["RS256"])
            assert claims["iss"] == "123" and claims["exp"] - claims["iat"] <= 600
            return httpx.Response(201, json={"token": "installation-test-token"})
        if request.url.path.endswith("/zip"):
            assert request.headers["Authorization"] == "Bearer installation-test-token"
            return httpx.Response(302, headers={"location": "https://reports.blob.core.windows.net/archive"})
        assert "Authorization" not in request.headers
        return httpx.Response(200, content=b"zip data")
    client.client = httpx.Client(transport=httpx.MockTransport(handler))
    assert client.artifact("TRM-MYOS/example", 1) == b"zip data"


def test_untrusted_download_redirect_is_rejected(client):
    client, _ = client
    client.token = "test"
    client.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": "http://localhost/private"})))
    with pytest.raises(GitHubError, match="Untrusted"):
        client.artifact("TRM-MYOS/example", 1)
