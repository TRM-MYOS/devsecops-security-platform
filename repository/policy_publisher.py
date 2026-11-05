"""Publish an approved threshold through a reviewable Central PR, using outbound API calls.

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
                      "permissions": {"contents": "write", "pull_requests": "write"}},
            )
            self._check(response)
            data = response.json()
            if (data.get("permissions", {}).get("contents") != "write"
                    or data.get("permissions", {}).get("pull_requests") != "write"
                    or not isinstance(data.get("token"), str) or not data["token"]):
                raise ValueError()
            self.token = data["token"]
            self.token_refresh_at = time.time() + 50 * 60
            return self.token
        except (httpx.HTTPError, GitHubError, KeyError, ValueError, TypeError) as error:
            raise PublicationError("Central publication needs an App installation with Contents and Pull requests write access to Central.") from error

    def request(self, method, suffix, *, params=None, body=None, missing=False):
        try:
            response = self.client.request(
                method, f"https://api.github.com/repos/{CENTRAL_REPOSITORY}/{suffix}",
                params=params, json=body,
                headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json"},
            )
            if missing and response.status_code == 404:
                return None
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


def _mutate(client, actor_id, version, method, suffix, body):
    # Account updates and threshold changes cannot commit during this remote write.
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _authorize(connection, actor_id, version)
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


def _pull(client, data):
    rows = client.request("GET", "pulls", params={"head": f"{CENTRAL_REPOSITORY.split('/')[0]}:{data['branch']}",
                                                   "base": BASE_BRANCH, "state": "all", "per_page": 100})
    if not isinstance(rows, list):
        raise PublicationError("Central returned an invalid pull request list.")
    matches = [row for row in rows if row.get("head", {}).get("ref") == data["branch"]
               and row.get("head", {}).get("repo", {}).get("full_name", "").casefold() == CENTRAL_REPOSITORY.casefold()
               and row.get("base", {}).get("ref") == BASE_BRANCH]
    if len(matches) > 1:
        raise PublicationError("More than one pull request matches this publication; review Central manually.")
    return matches[0] if matches else None


def _set_pull(data, pull):
    number = pull.get("number")
    if type(number) is not int or number < 1:
        raise PublicationError("Central returned an invalid pull request number.")
    data.update(pr_number=number, pr_url=f"https://github.com/{CENTRAL_REPOSITORY}/pull/{number}",
                state="awaiting_merge" if pull.get("state") == "open" else "closed")


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
        data = read(version) or {"version": version, "minimum_score": desired["minimum_score"],
                                 "branch": f"dashboard-policy/{version}", "state": "preparing"}
        client = PolicyGitHubClient()
        try:
            main = client.request("GET", f"branches/{BASE_BRANCH}")
            base = _sha(main["commit"]["sha"])
            if client.request("GET", "contents/security-policy-source.json", params={"ref": base}, missing=True) is not None:
                raise PublicationError("Central has an HTTPS policy source. Review that configuration before publishing a repository policy.")
            main_item, config = _file(client, base)
            if config["policy"].get("version") == version and config["policy"]["minimum_score"] == data["minimum_score"]:
                data.update(state="merged", commit_sha=base)
                data.pop("error", None)
                _persist(actor_id, data, "policy.published")
                return data
            if data.get("base_sha") and data["base_sha"] != base:
                raise PublicationError("Central main changed. Save a new threshold version before creating another publication.")
            data["base_sha"] = base
            _persist(actor_id, data, "policy.publish_requested")
            existing_pull = _pull(client, data)
            if existing_pull and existing_pull.get("state") != "open":
                _set_pull(data, existing_pull)
                data.pop("error", None)
                _persist(actor_id, data)
                return data
            branch = client.request("GET", f"git/ref/heads/{data['branch']}", missing=True)
            if branch is None:
                _mutate(client, actor_id, version, "POST", "git/refs", {"ref": f"refs/heads/{data['branch']}", "sha": base})
            _, candidate = _file(client, data["branch"])
            config["policy"].update(minimum_score=data["minimum_score"], version=version)
            expected = yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
            if candidate != config:
                # Never overwrite a branch modified by another writer.
                branch = client.request("GET", f"git/ref/heads/{data['branch']}")
                if _sha(branch["object"]["sha"]) != base:
                    raise PublicationError("The publication branch was changed by another writer. Review it before retrying.")
                result = _mutate(client, actor_id, version, "PUT", f"contents/{POLICY_PATH}", {
                    "message": f"policy: minimum score {data['minimum_score']}/100 ({version})",
                    "branch": data["branch"], "sha": main_item["sha"],
                    "content": base64.b64encode(expected.encode()).decode(),
                })
                data["commit_sha"] = _sha(result["commit"]["sha"])
                _persist(actor_id, data)
            comparison = client.request("GET", f"compare/{base}...{data['branch']}")
            files = comparison.get("files", [])
            if (comparison.get("merge_base_commit", {}).get("sha") != base or len(files) != 1
                    or files[0].get("filename") != POLICY_PATH or files[0].get("status") != "modified"):
                raise PublicationError("Publication must change only Central security-policy.yaml; review the branch manually.")
            if existing_pull:
                _set_pull(data, existing_pull)
                data.pop("error", None)
                _persist(actor_id, data)
                return data
            pull = _mutate(client, actor_id, version, "POST", "pulls", {
                "title": f"Security policy: minimum score {data['minimum_score']}/100",
                "head": data["branch"], "base": BASE_BRANCH, "maintainer_can_modify": False,
                "body": f"Approved for publication by a Dashboard Super User.\n\nPolicy version: `{version}`\n\nMinimum passing score: **{data['minimum_score']}/100**.\n\nHIGH/CRITICAL still BLOCK. Existing scan history is unchanged. Review and merge through the normal Central protection rules; this PR does not bypass them.",
            })
            _set_pull(data, pull)
            data.pop("error", None)
            _persist(actor_id, data)
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
            main = client.request("GET", f"branches/{BASE_BRANCH}")
            head = _sha(main["commit"]["sha"])
            if client.request("GET", "contents/security-policy-source.json", params={"ref": head}, missing=True) is not None:
                raise PublicationError("Central has an HTTPS policy source; repository policy activation cannot be confirmed.")
            _, config = _file(client, head)
            if config["policy"].get("version") == version and config["policy"]["minimum_score"] == data["minimum_score"]:
                data.update(state="merged", commit_sha=head)
            else:
                pull = _pull(client, data)
                if pull:
                    _set_pull(data, pull)
                    if pull.get("merged_at"):
                        data["state"] = "superseded"
                else:
                    data["state"] = "failed"
                    data["error"] = "No pull request found. Retry publication to reconcile the same version."
            if data["state"] != "failed":
                data.pop("error", None)
            _persist(actor_id, data, "policy.publication_checked")
            return data
        except (GitHubError, KeyError, TypeError, ValueError, RuntimeError) as error:
            message = str(error) if isinstance(error, PublicationError) else "Cannot verify Central publication. No new activation was confirmed."
            raise PublicationError(message) from error
        finally:
            client.close()
