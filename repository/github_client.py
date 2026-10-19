"""Read-only GitHub App access. Credentials never leave the backend."""

import os
import time
from pathlib import Path

import httpx


class GitHubError(RuntimeError):
    pass


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
GITHUB_KEYS = (
        "DEVSECOPS_GITHUB_APP_ID", "DEVSECOPS_GITHUB_INSTALLATION_ID",
        "DEVSECOPS_GITHUB_PRIVATE_KEY_PATH", "DEVSECOPS_GITHUB_WORKFLOW",
)


def configuration():
    """Read local GitHub settings regardless of the server launcher or working directory.

    Never execute file contents or modify the process environment. Explicit nonempty
    environment variables take precedence; unrelated .env keys are ignored here.
    """
    values = {}
    try:
        for line in ENV_PATH.read_text(encoding="utf-8-sig").splitlines():
            key, separator, value = line.strip().partition("=")
            key = key.strip()
            if separator and key in GITHUB_KEYS:
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                values[key] = value
    except (OSError, UnicodeError):
        pass
    for key in GITHUB_KEYS:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def configured():
    settings = configuration()
    return all(settings.get(key) for key in GITHUB_KEYS[:3])


class GitHubClient:
    def __init__(self):
        self.client = httpx.Client(timeout=30, follow_redirects=False)
        self.token = None
        self.token_refresh_at = None

    def close(self):
        self.client.close()

    def _token(self):
        settings = configuration()
        if not all(settings.get(key) for key in GITHUB_KEYS[:3]):
            raise GitHubError("GitHub App is not configured. See README: GitHub Actions monitoring.")
        if self.token and (self.token_refresh_at is None or time.time() < self.token_refresh_at):
            return self.token
        try:
            import jwt
        except ImportError as error:
            raise GitHubError("Install requirements.txt to enable GitHub App signing") from error
        try:
            now = int(time.time())
            signed = jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": settings["DEVSECOPS_GITHUB_APP_ID"]},
                Path(settings["DEVSECOPS_GITHUB_PRIVATE_KEY_PATH"]).read_bytes(),
                algorithm="RS256",
            )
            installation = int(settings["DEVSECOPS_GITHUB_INSTALLATION_ID"])
        except (OSError, ValueError, jwt.PyJWTError) as error:
            raise GitHubError("Cannot load GitHub App credentials or signing dependencies") from error
        try:
            response = self.client.post(
                f"https://api.github.com/app/installations/{installation}/access_tokens",
                headers={"Authorization": f"Bearer {signed}", "Accept": "application/vnd.github+json"},
                json={"permissions": {"contents": "read", "actions": "read"}},
            )
        except httpx.HTTPError as error:
            raise GitHubError("Cannot authenticate GitHub App") from error
        self._check(response)
        self.token = response.json()["token"]
        self.token_refresh_at = time.time() + 50 * 60
        return self.token

    @staticmethod
    def _check(response):
        if response.status_code >= 400:
            raise GitHubError(f"GitHub returned HTTP {response.status_code}; check App access, permissions and rate limits")

    def get(self, path, params=None):
        try:
            response = self.client.get(
                f"https://api.github.com{path}", params=params,
                headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json"},
            )
            self._check(response)
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise GitHubError("Cannot read GitHub response") from error

    def artifact(self, full_name, artifact_id):
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json"}
        try:
            response = self.client.get(
                f"https://api.github.com/repos/{full_name}/actions/artifacts/{int(artifact_id)}/zip",
                headers=headers,
            )
            self._check(response)
            if response.status_code != 302:
                raise GitHubError("GitHub did not return an artifact download URL")
            url = httpx.URL(response.headers["location"])
            if url.scheme != "https" or not url.host.endswith((".githubusercontent.com", ".blob.core.windows.net")):
                raise GitHubError("Untrusted artifact download host")
            # Do not forward the installation token to blob storage.
            with self.client.stream("GET", url) as download:
                self._check(download)
                content = bytearray()
                for chunk in download.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 20 * 1024 * 1024:
                        raise GitHubError("Artifact exceeds the 20 MB download limit")
                return bytes(content)
        except (httpx.HTTPError, KeyError, ValueError) as error:
            raise GitHubError("Cannot download security reports") from error
