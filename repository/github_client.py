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
        "DEVSECOPS_GITHUB_OWNER",
)


def environment_configuration():
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


def configuration():
    from repository.owner_settings import current
    return current()


def configured():
    settings = configuration()
    return all(settings.get(key) for key in GITHUB_KEYS[:3])


class GitHubClient:
    def __init__(self, settings=None):
        self.settings = dict(configuration() if settings is None else settings)
        self.client = httpx.Client(timeout=30, follow_redirects=False)
        self.token = None
        self.token_refresh_at = None

    def close(self):
        self.client.close()

    def _app_jwt(self):
        settings = self.settings
        if not all(settings.get(key) for key in GITHUB_KEYS[:3]):
            raise GitHubError("GitHub App is not configured. See README: GitHub Actions monitoring.")
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
        except (OSError, ValueError, jwt.PyJWTError) as error:
            raise GitHubError("Cannot load GitHub App credentials or signing dependencies") from error
        return signed

    def _token(self):
        if self.token and (self.token_refresh_at is None or time.time() < self.token_refresh_at):
            return self.token
        signed = self._app_jwt()
        try:
            installation = int(self.settings["DEVSECOPS_GITHUB_INSTALLATION_ID"])
        except (TypeError, ValueError) as error:
            raise GitHubError("Cannot load GitHub App installation ID") from error
        try:
            response = self.client.post(
                f"https://api.github.com/app/installations/{installation}/access_tokens",
                headers={"Authorization": f"Bearer {signed}", "Accept": "application/vnd.github+json"},
                json={"permissions": {"contents": "read", "actions": "read"}},
            )
        except httpx.HTTPError as error:
            raise GitHubError("Cannot authenticate GitHub App") from error
        self._check(response)
        try:
            token = response.json()["token"]
            if not isinstance(token, str) or not token:
                raise ValueError("Invalid token")
        except (ValueError, KeyError, TypeError) as error:
            raise GitHubError("Invalid GitHub authentication response") from error
        self.token = token
        self.token_refresh_at = time.time() + 50 * 60
        return self.token

    def check_connection(self, owner):
        """Check App identity, installation owner/permissions, then read using its token."""
        try:
            headers = {"Authorization": f"Bearer {self._app_jwt()}", "Accept": "application/vnd.github+json"}
            app = self.client.get("https://api.github.com/app", headers=headers)
            self._check(app)
            if str(app.json()["id"]) != self.settings["DEVSECOPS_GITHUB_APP_ID"]:
                raise GitHubError("App ID does not match the signing key")
            installation = self.client.get(
                f"https://api.github.com/app/installations/{int(self.settings['DEVSECOPS_GITHUB_INSTALLATION_ID'])}", headers=headers,
            )
            self._check(installation)
            data = installation.json()
            if str(data["app_id"]) != self.settings["DEVSECOPS_GITHUB_APP_ID"]:
                raise GitHubError("Installation does not belong to this App")
            if data["account"]["login"].casefold() != owner.casefold():
                raise GitHubError("GitHub Owner does not match the installation account")
            if data.get("suspended_at"):
                raise GitHubError("GitHub App installation is suspended")
            if any(data.get("permissions", {}).get(p) not in {"read", "write"} for p in ("actions", "contents", "metadata")):
                raise GitHubError("Installation needs Actions, Contents and Metadata read access")
            repositories = self.get("/installation/repositories", params={"per_page": 1})
            if not isinstance(repositories.get("repositories"), list) or type(repositories.get("total_count")) is not int:
                raise GitHubError("Invalid GitHub repository access response")
            return {"owner": data["account"]["login"], "repositories_accessible": repositories["total_count"],
                    "message": "GitHub App connection verified. Workflow availability is checked when each repository syncs."}
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise GitHubError("Cannot verify GitHub App connection") from error

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
