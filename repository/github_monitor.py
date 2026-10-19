"""Import retained Central push runs and exact branch-head snapshots; never scan here."""

import io
import json
import threading
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

from repository.database import get_connection
from repository.github_client import GitHubClient, GitHubError, configuration
from scanner.repository_scanner import validate_repository
from security.parser import parse_reports, build_summary


SYNC_LOCK = threading.RLock()
REPOSITORY_SYNC_LOCK = threading.Lock()


def sync_all_branches(manager, repository_id, client=None):
    """Discover branches on every poll, including branches created after enrollment."""
    repository = manager.get_repository(repository_id)
    if repository is None:
        raise ValueError("Repository not found")
    validate_repository(repository["url"])
    full_name = repository["url"].rstrip("/").split("github.com/", 1)[1]
    if full_name.endswith(".git"):
        full_name = full_name[:-4]
    own_client = client is None
    client = client or GitHubClient()
    with REPOSITORY_SYNC_LOCK:
        try:
            names = []
            page = 1
            while True:
                rows = client.get(f"/repos/{full_name}/branches", params={"per_page": 100, "page": page})
                if not isinstance(rows, list):
                    raise GitHubError("Invalid GitHub branch list")
                for row in rows:
                    name = row["name"]
                    if not isinstance(name, str) or not name or len(name) > 255:
                        raise GitHubError("Invalid GitHub branch name")
                    names.append(name)
                if len(rows) < 100:
                    break
                page += 1
            results = []
            for name in dict.fromkeys(names):
                try:
                    result = sync_repository(manager, repository_id, branch=name, client=client, publish=False)
                except Exception:
                    result = {"branch": name, "execution_status": "error", "policy_status": None,
                              "message": "Could not synchronize this branch"}
                results.append(result)
            try:
                history = sync_push_history(manager, repository_id, client=client)
            except (GitHubError, ValueError, KeyError, TypeError) as error:
                history = {"status": "error", "message": str(error)}
            # Repository summary is a UI classification, not a new policy decision.
            data = {"execution_status": "monitoring", "policy_status": None,
                    "source": "github_actions", "full_name": full_name, "branches": results, "history": history,
                    "findings": sum(r.get("findings", 0) for r in results if r.get("execution_status") == "completed")}
            return _store(repository_id, data)
        except (GitHubError, KeyError, TypeError) as error:
            return _store(repository_id, {"execution_status": "error", "policy_status": None,
                                         "branches": [], "message": str(error) if isinstance(error, GitHubError) else "Invalid GitHub response"})
        finally:
            if own_client:
                client.close()


def poll_repositories(manager, stop, interval=30):
    """Backend polling continues even when no browser is open."""
    from repository.github_client import configured
    while not stop.is_set():
        if configured():
            try:
                for repository in manager.get_repositories():
                    if stop.is_set():
                        break
                    try:
                        sync_all_branches(manager, repository["id"])
                    except Exception:
                        continue
            except Exception:
                pass
        stop.wait(interval)


def tracking(repository_id):
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT data FROM github_tracking WHERE repository_id = ?", (repository_id,)).fetchone()
    return json.loads(row["data"]) if row else {"execution_status": "not_synced", "policy_status": None}


def scan_metadata(scan_id):
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT metadata FROM github_imports WHERE scan_id = ?", (scan_id,)).fetchone()
    return json.loads(row["metadata"]) if row else None


def _store(repository_id, data, publish=True):
    data["synced_at"] = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as connection, connection:
        if publish:
            connection.execute(
                "INSERT INTO github_tracking VALUES (?, ?) ON CONFLICT(repository_id) DO UPDATE SET data=excluded.data",
                (repository_id, json.dumps(data)),
            )
        if data.get("branch") and "branches" not in data:
            connection.execute(
                "INSERT INTO github_branches VALUES (?, ?, ?) ON CONFLICT(repository_id, branch) DO UPDATE SET data=excluded.data",
                (repository_id, data["branch"], json.dumps(data)),
            )
    return data


def read_reports(content):
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            required = {"bandit.json", "trivy.json", "gitleaks.json", "security-summary.json"}
            files = {}
            for item in archive.infolist():
                name = Path(item.filename).name
                if name not in required:
                    continue
                if name in files or item.file_size > 10 * 1024 * 1024:
                    raise GitHubError("Duplicate or oversized security report")
                files[name] = archive.read(item)
            if set(files) != required:
                raise GitHubError("Security artifact is missing required reports")
        summary = json.loads(files["security-summary.json"])
        if not isinstance(summary, dict):
            raise GitHubError("Invalid Central summary")
        if summary.get("status") not in {"ALLOW", "BLOCK"}:
            raise GitHubError("Invalid Central policy decision")
        if type(summary.get("score")) is not int or not 0 <= summary["score"] <= 100:
            raise GitHubError("Invalid Central score")
        if summary.get("grade") not in {"A", "B", "C", "D", "F"} or not isinstance(summary.get("reason"), str):
            raise GitHubError("Invalid Central grade or reason")
        with TemporaryDirectory(prefix="central-import-") as directory:
            for name, content in files.items():
                Path(directory, name).write_bytes(content)
            findings = parse_reports(*(Path(directory, name) for name in ("bandit.json", "trivy.json", "gitleaks.json")))
        expected = build_summary(findings, summary["score"], summary["grade"], summary)
        if any(summary.get(key) != value for key, value in expected.items()):
            raise GitHubError("Central summary does not match scanner reports")
        return summary
    except (SystemExit, ValueError, OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, GitHubError):
            raise
        raise GitHubError("Security reports failed validation") from error


TRUSTED_WORKFLOW = "TRM-MYOS/devsecops-security-platform/.github/workflows/security-scan.yml@main"
TRUSTED_JOB = "Central Security Gate / Run Central Security Scan"
VALIDATION_VERSION = 2


def _full_name(repository):
    validate_repository(repository["url"])
    return repository["url"].rstrip("/").split("github.com/", 1)[1].removesuffix(".git")


def _pages(client, path, key, params=None):
    page = 1
    while True:
        payload = client.get(path, params={**(params or {}), "per_page": 100, "page": page})
        rows = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise GitHubError(f"Invalid GitHub {key} list")
        if not all(isinstance(row, dict) for row in rows):
            raise GitHubError(f"Invalid GitHub {key} item")
        yield from rows
        if len(rows) < 100:
            break
        page += 1


def _producer(client, full_name, run):
    references = run.get("referenced_workflows")
    if references is None:
        references = client.get(f"/repos/{full_name}/actions/runs/{run['id']}/attempts/{run.get('run_attempt', 1)}").get("referenced_workflows")
    if not isinstance(references, list) or not all(isinstance(item, dict) for item in references):
        raise GitHubError("Invalid reusable workflow reference metadata")
    trusted = [item for item in references if isinstance(item.get("path"), str) and item["path"].casefold() == TRUSTED_WORKFLOW.casefold()]
    if len(trusted) != 1 or not isinstance(trusted[0].get("sha"), str) or len(trusted[0]["sha"]) != 40 or any(char not in "0123456789abcdef" for char in trusted[0]["sha"].lower()):
        raise GitHubError("Run does not reference the trusted Central reusable workflow")
    jobs = list(_pages(client, f"/repos/{full_name}/actions/runs/{run['id']}/attempts/{run.get('run_attempt', 1)}/jobs", "jobs"))
    # The connector must contain only the Central job: no second artifact producer.
    if len(jobs) != 1 or jobs[0].get("name") != TRUSTED_JOB or jobs[0].get("status") != "completed" or jobs[0].get("conclusion") not in {"success", "failure"}:
        raise GitHubError("Run must contain exactly one completed trusted Central security job")
    if jobs[0].get("head_sha", run["head_sha"]) != run["head_sha"]:
        raise GitHubError("Central job commit does not match run")
    return {"central_workflow": trusted[0]["path"], "central_sha": trusted[0]["sha"], "job_conclusion": jobs[0]["conclusion"]}


def _record_run(repository_id, data):
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT INTO github_run_history VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(repository_id, run_id, attempt)
               DO UPDATE SET scan_id=excluded.scan_id, data=excluded.data""",
            (repository_id, data["run_id"], data["run_attempt"], data.get("scan_id"), json.dumps(data)),
        )
    return data


def run_history(repository_id=None):
    """Unvalidated/unfinished attempts stay visible without a score or policy decision."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            """SELECT h.*, r.name FROM github_run_history h JOIN repositories r ON r.id=h.repository_id
               WHERE h.scan_id IS NULL AND (? IS NULL OR h.repository_id=?)""",
            (repository_id, repository_id),
        ).fetchall()
    result = []
    for row in rows:
        data = json.loads(row["data"])
        result.append({
            "id": f"run-{row['repository_id']}-{row['run_id']}-{row['attempt']}",
            "repository_id": row["repository_id"], "repository_name": row["name"],
            "scanned_at": data.get("run_updated_at"), "score": None, "grade": None,
            "status": None, "reason": data.get("message") or "No validated policy decision",
            "findings": None, "report_available": False,
            "execution_status": data["execution_status"], "github": data,
        })
    return result


def _inspect_run(manager, repository, run, client, metadata=None, before=None):
    full_name = _full_name(repository)
    repository_id = repository["id"]
    attempt = run.get("run_attempt", 1)
    commit = run.get("head_commit") or {}
    author = commit.get("author") or {}
    data = {"source": "github_actions", "full_name": full_name, "branch": run["head_branch"],
            "commit_sha": run["head_sha"], "commit_message": commit.get("message"),
            "commit_author": author.get("name"), "commit_time": commit.get("timestamp"),
            **(metadata or {}), "run_id": run["id"], "run_attempt": attempt,
            "run_url": f"https://github.com/{full_name}/actions/runs/{run['id']}",
            "run_updated_at": run.get("updated_at"), "conclusion": run.get("conclusion"),
            "pushed_by": (run.get("actor") or {}).get("login"),
            "execution_status": "waiting", "policy_status": None}
    try:
        if run.get("event") != "push" or run.get("repository", {}).get("full_name", full_name).casefold() != full_name.casefold():
            raise GitHubError("Run does not belong to this repository push workflow")
        if run["status"] != "completed":
            data["execution_status"] = "running" if run["status"] == "in_progress" else "queued"
            return _record_run(repository_id, data)
        if run.get("conclusion") not in {"success", "failure"}:
            raise GitHubError(f"Workflow ended: {run.get('conclusion')}")
        with closing(get_connection()) as connection:
            existing = connection.execute("SELECT scan_id, metadata FROM github_imports WHERE repository_id=? AND run_id=? AND attempt=?",
                                          (repository_id, run["id"], attempt)).fetchone()
        cached_metadata = json.loads(existing["metadata"]) if existing else {}
        provenance = cached_metadata.get("producer")
        data["producer"] = provenance or _producer(client, full_name, run)
        if existing and cached_metadata.get("validation_version") == VALIDATION_VERSION:
            with closing(get_connection()) as connection:
                saved = connection.execute("SELECT * FROM scans WHERE id=?", (existing["scan_id"],)).fetchone()
            if saved["status"] == "ALLOW" and (run["conclusion"] != "success" or data["producer"]["job_conclusion"] != "success"):
                raise GitHubError("Failed workflow cannot supply an ALLOW decision")
            if not provenance:
                original = json.loads(existing["metadata"])
                original["producer"] = data["producer"]
                with closing(get_connection()) as connection, connection:
                    connection.execute("UPDATE github_imports SET metadata=? WHERE repository_id=? AND run_id=? AND attempt=?",
                                       (json.dumps(original), repository_id, run["id"], attempt))
            data.update(execution_status="completed", policy_status=saved["status"], scan_id=existing["scan_id"], findings=saved["findings"])
            return _record_run(repository_id, data)
        candidates = []
        for artifact in _pages(client, f"/repos/{full_name}/actions/runs/{run['id']}/artifacts", "artifacts"):
            if artifact.get("name") != "security-reports" or artifact.get("expired"):
                continue
            if artifact["created_at"] < run["run_started_at"] or (before and artifact["created_at"] >= before):
                continue
            identity = artifact.get("workflow_run")
            if identity is not None and not isinstance(identity, dict):
                raise GitHubError("Invalid artifact workflow run identity")
            if identity and (identity.get("id") != run["id"] or identity.get("head_sha") != run["head_sha"]):
                raise GitHubError("Artifact commit or workflow run does not match")
            candidates.append(artifact)
        if len(candidates) != 1:
            raise GitHubError("No unambiguous security report for this run attempt")
        summary = read_reports(client.artifact(full_name, candidates[0]["id"]))
        if summary["status"] == "ALLOW" and (run["conclusion"] != "success" or data["producer"]["job_conclusion"] != "success"):
            raise GitHubError("Failed workflow cannot supply an ALLOW decision")
        data["validation_version"] = VALIDATION_VERSION
        with closing(get_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if existing:
                # Revalidate pre-upgrade imports once; never silently trust cached ALLOW.
                scan_id = existing["scan_id"]
                saved = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                previous_findings = [dict(row) for row in connection.execute("SELECT scanner,category,severity,confidence,file,line,rule_id,message,cwe FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))]
                if any(saved[key] != summary[key] for key in ("score", "grade", "status", "reason", "findings")) or previous_findings != summary["findings_data"]:
                    raise GitHubError("Stored scan does not match the validated Central report")
                connection.execute("UPDATE github_imports SET metadata=? WHERE repository_id=? AND run_id=? AND attempt=?",
                                   (json.dumps(data), repository_id, run["id"], attempt))
            else:
                scan_id = manager.save_scan(repository_id, run["updated_at"], summary["score"], summary["grade"],
                                            summary["status"], summary["reason"], summary["findings_data"], connection=connection)
                connection.execute("INSERT INTO github_imports VALUES (?, ?, ?, ?, ?)",
                                   (repository_id, run["id"], attempt, scan_id, json.dumps(data)))
        data.update(execution_status="completed", policy_status=summary["status"], scan_id=scan_id, findings=summary["findings"])
    except (GitHubError, KeyError, TypeError, ValueError) as error:
        data.update(execution_status="error", policy_status=None,
                    message=str(error) if isinstance(error, GitHubError) else "Invalid GitHub response")
        data.pop("scan_id", None)
    return _record_run(repository_id, data)


def sync_push_history(manager, repository_id, client):
    """Page through all retained workflow runs, including deleted branches and older heads.

    Do not filter the API query by event: GitHub caps filtered searches at 1000 runs.
    Pull-request runs are filtered locally. Missing/expired reports are recorded as errors.
    """
    repository = manager.get_repository(repository_id)
    full_name = _full_name(repository)
    workflow = quote(configuration().get("DEVSECOPS_GITHUB_WORKFLOW") or "security-gate-test.yml", safe="")
    latest = list(_pages(client, f"/repos/{full_name}/actions/workflows/{workflow}/runs", "workflow_runs"))
    results = []
    with SYNC_LOCK:
        for run in sorted((r for r in latest if r.get("event") == "push"), key=lambda r: r["run_number"]):
            next_start = None
            for attempt in range(run.get("run_attempt", 1), 0, -1):
                try:
                    candidate = run if attempt == run.get("run_attempt", 1) else client.get(f"/repos/{full_name}/actions/runs/{run['id']}/attempts/{attempt}")
                    result = _inspect_run(manager, repository, candidate, client, before=next_start)
                    next_start = candidate.get("run_started_at")
                    results.append(result)
                except (GitHubError, KeyError, TypeError, ValueError) as error:
                    data = {"source": "github_actions", "full_name": full_name, "branch": run.get("head_branch"),
                            "commit_sha": run.get("head_sha"), "run_id": run["id"], "run_attempt": attempt,
                            "run_updated_at": run.get("updated_at"), "execution_status": "error", "policy_status": None,
                            "message": f"Could not synchronize run attempt: {error}"}
                    _record_run(repository_id, data)
                    results.append(data)
    return {"status": "completed", "attempts": len(results), "failed": sum(r["execution_status"] == "error" for r in results)}


def sync_repository(manager, repository_id, branch=None, client=None, publish=True):
    repository = manager.get_repository(repository_id)
    if repository is None:
        raise ValueError("Repository not found")
    full_name = _full_name(repository)
    own_client = client is None
    client = client or GitHubClient()
    data = {"execution_status": "waiting", "policy_status": None, "source": "github_actions", "full_name": full_name}
    with SYNC_LOCK:
        try:
            branch = branch or tracking(repository_id).get("branch")
            if branch:
                data["branch"] = branch
            info = client.get(f"/repos/{full_name}")
            branch = branch or info["default_branch"]
            if not isinstance(branch, str) or not branch or len(branch) > 255:
                raise GitHubError("Invalid branch")
            commit = client.get(f"/repos/{full_name}/commits/{quote(branch, safe='')}")
            sha = commit["sha"]
            data.update(branch=branch, commit_sha=sha, commit_message=commit["commit"]["message"],
                        commit_author=commit["commit"]["author"]["name"], commit_time=commit["commit"]["author"]["date"])
            workflow = quote(configuration().get("DEVSECOPS_GITHUB_WORKFLOW") or "security-gate-test.yml", safe="")
            matches = [r for r in _pages(client, f"/repos/{full_name}/actions/workflows/{workflow}/runs", "workflow_runs",
                       {"event": "push", "branch": branch, "head_sha": sha})
                       if r["head_sha"] == sha and r["head_branch"] == branch and r["event"] == "push"]
            if not matches:
                data["message"] = "No push scan for this commit. Check the workflow trigger and selected branch."
                return _store(repository_id, data, publish=publish)
            run = max(matches, key=lambda r: (r["run_number"], r.get("run_attempt", 1)))
            result = _inspect_run(manager, repository, run, client, metadata=data)
            return _store(repository_id, result, publish=publish)
        except (GitHubError, KeyError, TypeError) as error:
            data.update(execution_status="error", policy_status=None,
                        message=str(error) if isinstance(error, GitHubError) else "Invalid GitHub response")
            return _store(repository_id, data, publish=publish)
        finally:
            if own_client:
                client.close()
