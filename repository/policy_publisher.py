"""Apply an approved threshold directly to Central main, using outbound API calls.

The repository, base branch and writable path are pinned here. Target repositories
and request payloads cannot choose a different destination. Monitoring tokens stay
read-only; publication obtains a separate installation token scoped to Central.
"""

import base64
from contextlib import closing
from datetime import datetime, timezone
import json
import re
import threading
import time
from uuid import UUID

import httpx
import yaml

from auth.service import _audit, _check_account_administrator
from repository.database import get_connection
from repository.github_client import GitHubClient, GitHubError
from repository.owner_settings import settings_scope
from security.policy import validate_policy_config
from security.policy_source import source_config


CENTRAL_REPOSITORY = "TRM-MYOS/devsecops-security-platform"
BASE_BRANCH = "main"
POLICY_PATH = "security-policy.yaml"
LOCK = threading.Lock()
SHA = re.compile(r"[0-9a-f]{40}")


class PublicationError(RuntimeError):
    pass


class PolicyGitHubClient(GitHubClient):
    def _token(self):
        if self.token and time.time() < self.token_refresh_at:
            return self.token
        try:
            installation = int(self.settings["DEVSECOPS_GITHUB_INSTALLATION_ID"])
            response = self.client.post(
                f"https://api.github.com/app/installations/{installation}/access_tokens",
                headers={"Authorization": f"Bearer {self._app_jwt()}", "Accept": "application/vnd.github+json"},
                json={"repositories": [CENTRAL_REPOSITORY.split("/")[1]],
                      "permissions": {"contents": "write"}},
            )
            self._check(response)
            data = response.json()
            if (data.get("permissions", {}).get("contents") != "write"
                    or not isinstance(data.get("token"), str) or not data["token"]):
                raise ValueError()
            self.token = data["token"]
            self.token_refresh_at = time.time() + 50 * 60
            return self.token
        except (httpx.HTTPError, GitHubError, KeyError, ValueError, TypeError) as error:
            raise PublicationError("Cannot authenticate Policy apply. Check the App credentials, installation access to Central and Contents write permission.") from error

    def request(self, method, suffix, *, params=None, body=None, missing=False):
        try:
            response = self.client.request(
                method, f"https://api.github.com/repos/{CENTRAL_REPOSITORY}/{suffix}",
                params=params, json=body,
                headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json"},
            )
            if missing and response.status_code == 404:
                return None
            if response.status_code in {403, 404}:
                raise PublicationError("Central rejected Policy apply or access. Check Contents write permission and main branch rules; no protection rules were bypassed.")
            if response.status_code in {409, 422}:
                raise PublicationError("Central changed or a publication conflicts. Check publication status before retrying.")
            self._check(response)
            return response.json()
        except (httpx.HTTPError, GitHubError, ValueError, KeyError, TypeError) as error:
            raise PublicationError("Cannot publish to Central. Check App permissions and repository access, then retry the same version.") from error


def read(version):
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT data FROM policy_publications WHERE version=?", (version,)).fetchone()
    return json.loads(row["data"]) if row else None


def _authorize(connection, actor_id, version):
    from repository.policy_settings import current
    _check_account_administrator(connection, actor_id)
    desired = current()
    if desired["version"] != version:
        raise PublicationError("The saved threshold changed. Reload before publishing.")
    return desired


def _record(connection, data):
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    connection.execute("INSERT INTO policy_publications VALUES (?,?) ON CONFLICT(version) DO UPDATE SET data=excluded.data",
                       (data["version"], json.dumps(data)))


def _persist(actor_id, data, action=None):
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _authorize(connection, actor_id, data["version"])
        before = read(data["version"])
        _record(connection, data)
        if action:
            _audit(connection, actor_id, {"id": None, "username": "Security Policy"}, action,
                   {"state": (before or {}).get("state")},
                   {k: data[k] for k in ("version", "minimum_score", "state", "pr_number", "commit_sha") if k in data})


def _mutate(client, actor_id, version, method, suffix, body, *, expected_head):
    # Account updates and threshold changes cannot commit during this remote write.
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _authorize(connection, actor_id, version)
        head = _sha(client.request("GET", f"branches/{BASE_BRANCH}")["commit"]["sha"])
        if head != expected_head:
            raise PublicationError("Central main changed before apply. Check status and save a new version; no files were overwritten.")
        result = client.request(method, suffix, body=body)
        _audit(connection, actor_id, {"id": None, "username": "Security Policy"}, "policy.publication_write",
               None, {"version": version, "operation": f"{method} {suffix}"})
        return result


def _sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise PublicationError("Central returned an invalid commit identity.")
    return value


def _file(client, ref):
    item = client.request("GET", f"contents/{POLICY_PATH}", params={"ref": ref})
    try:
        if item["type"] != "file" or item["encoding"] != "base64" or item["size"] > 65536:
            raise ValueError()
        raw = base64.b64decode("".join(item["content"].split()), validate=True)
        if len(raw) > 65536:
            raise ValueError()
        config = validate_policy_config(yaml.safe_load(raw.decode("utf-8")))
        return item, config
    except (KeyError, ValueError, TypeError, RuntimeError, yaml.YAMLError) as error:
        raise PublicationError("Central security-policy.yaml is invalid; no files were published.") from error


def _main_policy(client):
    head = _sha(client.request("GET", f"branches/{BASE_BRANCH}")["commit"]["sha"])
    if client.request("GET", "contents/security-policy-source.json", params={"ref": head}, missing=True) is not None:
        raise PublicationError("Central has an HTTPS policy source. Repository Policy apply cannot be confirmed.")
    item, config = _file(client, head)
    _sha(item["sha"])
    return head, item, config


def _matches(config, data):
    return (config["policy"].get("version") == data["version"]
            and config["policy"]["minimum_score"] == data["minimum_score"])


@settings_scope
def publish(version, actor_id):
    try:
        if str(UUID(version)) != version:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as error:
        raise PublicationError("Save a threshold before publishing it.") from error
    with LOCK:
        with closing(get_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            desired = _authorize(connection, actor_id, version)
        if source_config():
            raise PublicationError("An HTTPS policy source is configured. Disable it through the Central review process before using repository publication.")
        data = read(version) or {"version": version, "minimum_score": desired["minimum_score"]}
        # Keep legacy PR metadata for audit/navigation, but never create or merge a PR.
        if data.get("method") != "direct" and data.get("base_sha"):
            data["legacy_base_sha"] = data.pop("base_sha")
        data.update(method="direct", branch=BASE_BRANCH)
        client = PolicyGitHubClient()
        try:
            base, main_item, config = _main_policy(client)
            if _matches(config, data):
                data.update(state="applied", commit_sha=base)
                data.pop("error", None)
                _persist(actor_id, data, "policy.published")
                return data
            if data.get("base_sha") and data["base_sha"] != base:
                raise PublicationError("Central main changed. Save a new threshold version before creating another publication.")
            data.update(base_sha=base, state="applying")
            _persist(actor_id, data, "policy.publish_requested")
            config["policy"].update(minimum_score=data["minimum_score"], version=version)
            expected = yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
            result = _mutate(client, actor_id, version, "PUT", f"contents/{POLICY_PATH}", {
                "message": f"policy: minimum score {data['minimum_score']}/100 ({version})",
                "branch": BASE_BRANCH, "sha": main_item["sha"],
                "content": base64.b64encode(expected.encode()).decode(),
            }, expected_head=base)
            data["write_commit_sha"] = _sha(result["commit"]["sha"])
            # A successful HTTP response is not evidence that main uses this version.
            head, _, applied = _main_policy(client)
            if not _matches(applied, data):
                raise PublicationError("The write was sent but Central main does not match. Check status before retrying; activation is not confirmed.")
            data.update(state="applied", commit_sha=head)
            data.pop("error", None)
            _persist(actor_id, data, "policy.published")
            return data
        except (PublicationError, GitHubError, KeyError, TypeError, ValueError, RuntimeError) as error:
            message = str(error) if isinstance(error, PublicationError) else "Central publication failed. Check configuration and retry the same version."
            data.update(state="failed", error=message)
            _persist(actor_id, data, "policy.publish_failed")
            raise PublicationError(message) from error
        finally:
            client.close()


@settings_scope
def check(version, actor_id):
    with LOCK:
        with closing(get_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            _authorize(connection, actor_id, version)
        data = read(version)
        if not data:
            raise PublicationError("This version has not been submitted for publication.")
        client = PolicyGitHubClient()
        try:
            head, _, config = _main_policy(client)
            if _matches(config, data):
                data.update(state="applied", commit_sha=head)
            else:
                was_applied = data.get("state") in {"applied", "merged", "superseded"} or data.get("write_commit_sha")
                data["state"] = "superseded" if was_applied else "failed"
                data["error"] = "Central main does not use this saved version. Apply it after review, or save a new version if Central changed."
            if data["state"] != "failed":
                data.pop("error", None)
            _persist(actor_id, data, "policy.publication_checked")
            return data
        except (GitHubError, KeyError, TypeError, ValueError, RuntimeError) as error:
            message = str(error) if isinstance(error, PublicationError) else "Cannot verify Central publication. No new activation was confirmed."
            raise PublicationError(message) from error
        finally:
            client.close()
