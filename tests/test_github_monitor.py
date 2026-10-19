"""Exact-commit monitoring and Central import; never contact GitHub in tests."""

import io
import json
import zipfile

import pytest

from repository import database, github_monitor as monitor
from repository.github_client import GitHubError
from repository.repository_manager import RepositoryManager
from security.parser import build_summary


SHA = "a" * 40


def artifact(status="ALLOW", broken=False):
    finding = {"scanner": "Gitleaks", "category": "SECRET", "severity": "HIGH", "confidence": None,
               "file": "config.py", "line": 1, "rule_id": "synthetic", "message": "Synthetic finding", "cwe": None}
    findings = [finding] if status == "BLOCK" else []
    files = {
        "bandit.json": {"results": [], "errors": []},
        "trivy.json": {"SchemaVersion": 2, "ArtifactName": "target", "ArtifactType": "filesystem"},
        "gitleaks.json": [{"File": "config.py", "StartLine": 1, "RuleID": "synthetic", "Description": "Synthetic finding"}] if findings else [],
        "security-summary.json": build_summary(findings, 75 if findings else 100, "C" if findings else "A", {"status": status, "reason": "Central decision"}),
    }
    if broken:
        files["bandit.json"] = {"results": [], "errors": [{"reason": "failed"}]}
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, json.dumps(value))
    return content.getvalue()


class Client:
    def __init__(self):
        self.run = {"id": 10, "run_number": 1, "run_attempt": 1, "head_sha": SHA, "head_branch": "main", "event": "push",
                    "status": "completed", "conclusion": "success", "actor": {"login": "pusher"},
                    "run_started_at": "2026-10-15T00:00:00Z", "updated_at": "2026-10-15T00:01:00Z"}
        self.run["referenced_workflows"] = [{"path": monitor.TRUSTED_WORKFLOW, "sha": "f" * 40}]
        self.runs = [self.run]
        self.artifacts = [{"id": 12, "name": "security-reports", "expired": False, "created_at": "2026-10-15T00:00:30Z"}]
        self.content = artifact()
        self.sha = SHA

    def get(self, path, params=None):
        if path.endswith("/jobs"):
            return {"jobs": [{"name": monitor.TRUSTED_JOB, "status": "completed", "conclusion": self.run["conclusion"]}]}
        if path.endswith("/branches"):
            return [{"name": "main"}]
        if path.endswith("/artifacts"):
            return {"artifacts": self.artifacts}
        if path.endswith("/runs"):
            return {"workflow_runs": self.runs}
        if "/commits/" in path:
            return {"sha": self.sha, "commit": {"message": "latest commit", "author": {"name": "author", "date": "2026-10-15T00:00:00Z"}}}
        return {"default_branch": "main"}

    def artifact(self, full_name, artifact_id):
        return self.content

    def close(self):
        pass


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "monitor.db")
    manager = RepositoryManager()
    repository = manager.add_repository("https://github.com/TRM-MYOS/example")
    return manager, repository["id"], Client()


def sync(environment):
    manager, repository_id, client = environment
    return monitor.sync_repository(manager, repository_id, client=client)


@pytest.mark.parametrize("status", ["ALLOW", "BLOCK"])
def test_imports_central_decision_without_recalculation_and_deduplicates(environment, status):
    manager, rid, client = environment
    client.content = artifact(status)
    client.run["conclusion"] = "failure" if status == "BLOCK" else "success"
    first = sync(environment)
    second = sync(environment)
    assert first["policy_status"] == status and second["scan_id"] == first["scan_id"]
    assert len(manager.get_scan_history(rid)) == 1
    assert monitor.scan_metadata(first["scan_id"])["commit_sha"] == SHA
    assert monitor.scan_metadata(first["scan_id"])["full_name"] == "TRM-MYOS/example"


def test_new_commit_does_not_reuse_old_allow(environment):
    manager, rid, client = environment
    assert sync(environment)["policy_status"] == "ALLOW"
    client.sha = "b" * 40
    result = sync(environment)
    assert result["execution_status"] == "waiting" and result["policy_status"] is None
    assert "scan_id" not in result
    assert len(manager.get_scan_history(rid)) == 1


@pytest.mark.parametrize("status,expected", [("queued", "queued"), ("in_progress", "running")])
def test_unfinished_run_has_no_gate(environment, status, expected):
    environment[2].run["status"] = status
    result = sync(environment)
    assert result["execution_status"] == expected and result["policy_status"] is None
    assert environment[0].get_all_scans() == []


@pytest.mark.parametrize("failure", ["missing", "expired", "stale", "broken", "invalid_zip", "failed_allow", "cancelled", "wrong_event", "wrong_branch"])
def test_fail_closed_reports_and_run_identity(environment, failure):
    manager, rid, client = environment
    if failure == "missing": client.artifacts = []
    elif failure == "expired": client.artifacts[0]["expired"] = True
    elif failure == "stale": client.artifacts[0]["created_at"] = "2025-01-01T00:00:00Z"
    elif failure == "broken": client.content = artifact(broken=True)
    elif failure == "invalid_zip": client.content = b"bad zip"
    elif failure == "failed_allow": client.run["conclusion"] = "failure"
    elif failure == "cancelled": client.run["conclusion"] = "cancelled"
    elif failure == "wrong_event": client.run["event"] = "pull_request"
    elif failure == "wrong_branch": client.run["head_branch"] = "other"
    result = sync(environment)
    assert result["execution_status"] in {"error", "waiting"}
    assert result["policy_status"] is None and manager.get_scan_history(rid) == []


def test_rerun_cannot_import_previous_attempt_artifact(environment):
    client = environment[2]
    sync(environment)
    client.run.update(run_attempt=2, run_started_at="2026-10-15T01:00:00Z")
    assert sync(environment)["execution_status"] == "error"
    assert len(environment[0].get_all_scans()) == 1


def test_connection_failure_preserves_selected_branch(environment):
    manager, rid, client = environment
    sync(environment)
    def unavailable(*args, **kwargs):
        raise GitHubError("GitHub unavailable")
    client.get = unavailable
    result = sync(environment)
    assert result["execution_status"] == "error"
    assert result["branch"] == "main"
    assert result["policy_status"] is None
    assert monitor.tracking(rid)["branch"] == "main"
    result = monitor.sync_repository(manager, rid, branch="test/security-block-v3", client=client)
    assert result["branch"] == "test/security-block-v3"


def test_missing_github_configuration_is_visible_without_scan(environment, monkeypatch):
    from repository import github_client
    monkeypatch.setattr(github_client, "ENV_PATH", github_client.ENV_PATH.parent / "missing-test-settings.env")
    for name in ("APP_ID", "INSTALLATION_ID", "PRIVATE_KEY_PATH"):
        monkeypatch.delenv("DEVSECOPS_GITHUB_" + name, raising=False)
    manager, rid, _ = environment
    result = monitor.sync_repository(manager, rid)
    assert result["execution_status"] == "error" and "not configured" in result["message"]
    assert manager.get_all_scans() == []


def test_import_transaction_rolls_back_if_metadata_write_fails(environment, monkeypatch):
    manager, rid, _ = environment
    original = manager.save_scan
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise GitHubError("simulated transaction failure")
    monkeypatch.setattr(manager, "save_scan", fail)
    assert sync(environment)["execution_status"] == "error"
    assert manager.get_scan_history(rid) == []
    assert manager.get_repository(rid)["status"] is None


class BranchClient(Client):
    def __init__(self):
        super().__init__()
        self.names = ["main", "test/new"]
        self.failed = set()
        self.unscanned = set()

    def get(self, path, params=None):
        from urllib.parse import unquote
        if path.endswith("/branches"):
            start = (params["page"] - 1) * 100
            return [{"name": name} for name in self.names[start:start + 100]]
        if "/commits/" in path:
            name = unquote(path.split("/commits/")[1])
            if name in self.failed:
                raise GitHubError("Branch unavailable")
            result = super().get(path, params)
            result["sha"] = f"{self.names.index(name) + 1:040x}"
            return result
        if path.endswith("/runs"):
            if not params.get("branch"):
                return {"workflow_runs": []}
            name = params["branch"]
            if name in self.unscanned:
                return {"workflow_runs": []}
            return {"workflow_runs": [{**self.run, "id": self.names.index(name) + 100,
                                      "head_branch": name, "head_sha": params["head_sha"]}]}
        return super().get(path, params)


def test_auto_discovers_all_branches_and_new_branches(environment):
    manager, rid, _ = environment
    client = BranchClient()
    first = monitor.sync_all_branches(manager, rid, client=client)
    assert {r["branch"] for r in first["branches"]} == set(client.names)
    assert all(r["policy_status"] == "ALLOW" for r in first["branches"])
    client.names.append("feature/automatic")
    second = monitor.sync_all_branches(manager, rid, client=client)
    assert len(second["branches"]) == 3
    assert len(manager.get_scan_history(rid)) == 3
    assert len(monitor.tracking(rid)["branches"]) == 3


def test_branch_failure_and_no_scan_do_not_hide_other_branches(environment):
    manager, rid, _ = environment
    client = BranchClient()
    client.names += ["feature/not-scanned"]
    client.failed.add("main")
    client.unscanned.add("feature/not-scanned")
    result = monitor.sync_all_branches(manager, rid, client=client)
    by_name = {r["branch"]: r for r in result["branches"]}
    assert by_name["main"]["execution_status"] == "error"
    assert by_name["test/new"]["policy_status"] == "ALLOW"
    assert by_name["feature/not-scanned"]["policy_status"] is None


def test_branch_discovery_pagination_and_deletions(environment):
    manager, rid, _ = environment
    client = BranchClient()
    client.names = [f"feature/{i}" for i in range(101)]
    client.unscanned = set(client.names)
    assert len(monitor.sync_all_branches(manager, rid, client=client)["branches"]) == 101
    client.names = ["feature/0"]
    assert len(monitor.sync_all_branches(manager, rid, client=client)["branches"]) == 1
    assert manager.get_scan_history(rid) == []


def test_backend_poller_runs_without_browser_and_continues_after_repo_error(environment, monkeypatch):
    import threading
    from repository import github_client
    manager, rid, _ = environment
    manager.add_repository("https://github.com/TRM-MYOS/another")
    monkeypatch.setattr(github_client, "configured", lambda: True)
    stop = threading.Event()
    calls = []
    def poll(manager, repository_id):
        calls.append(repository_id)
        if len(calls) == 1:
            raise GitHubError("unavailable")
        stop.set()
    monkeypatch.setattr(monitor, "sync_all_branches", poll)
    monitor.poll_repositories(manager, stop, interval=0)
    assert len(calls) == 2


def test_backfills_all_heads_without_replacing_current_branch_snapshot(environment):
    manager, rid, client = environment
    client.runs = [{**client.run, "id": n, "run_number": n, "head_sha": f"{n:040x}",
                    "updated_at": f"2026-10-{n:02d}T00:01:00Z"} for n in range(15, 18)]
    client.run = client.runs[-1]
    client.sha = client.run["head_sha"]
    first = sync(environment)
    monitor.sync_push_history(manager, rid, client)
    assert len(manager.get_all_scans()) == 3
    assert monitor.tracking(rid)["commit_sha"] == first["commit_sha"]
    assert manager.get_repository(rid)["last_scan"] == client.run["updated_at"]
    monitor.sync_push_history(manager, rid, client)
    assert len(manager.get_all_scans()) == 3


def test_history_pages_over_100_runs_including_deleted_branches(environment):
    manager, rid, client = environment
    original = client.get
    pages = []
    def get(path, params=None):
        if path.endswith('/runs'):
            assert 'event' not in params and 'head_sha' not in params
            pages.append(params['page'])
            start = (params['page'] - 1) * 100
            runs = [{**client.run, 'id': i + 1000, 'run_number': i + 1, 'head_branch': 'deleted-branch',
                     'conclusion': 'cancelled'} for i in range(105)]
            return {'workflow_runs': runs[start:start+100]}
        return original(path, params)
    client.get = get
    result = monitor.sync_push_history(manager, rid, client)
    assert pages == [1, 2] and result['attempts'] == 105
    assert len(monitor.run_history(rid)) == 105
    assert all(row['status'] is None and row['score'] is None for row in monitor.run_history(rid))


@pytest.mark.parametrize('failure', ['missing-reference', 'wrong-workflow', 'extra-job', 'wrong-artifact-sha'])
def test_untrusted_artifact_producer_has_no_allow(environment, failure):
    manager, rid, client = environment
    original = client.get
    if failure == 'missing-reference': client.run['referenced_workflows'] = []
    if failure == 'wrong-workflow': client.run['referenced_workflows'][0]['path'] = 'attacker/repo/workflow.yml@main'
    if failure == 'wrong-artifact-sha': client.artifacts[0]['workflow_run'] = {'id':10,'head_sha':'b'*40}
    if failure == 'extra-job':
        def get(path, params=None):
            data = original(path, params)
            if path.endswith('/jobs'): data['jobs'].append({'name':'fake artifact producer'})
            return data
        client.get = get
    result = sync(environment)
    assert result['execution_status'] == 'error' and result['policy_status'] is None
    assert manager.get_all_scans() == []
    assert monitor.run_history(rid)[0]['status'] is None


def test_failed_report_is_retained_in_history_and_can_recover(environment):
    manager, rid, client = environment
    client.content = artifact(broken=True)
    monitor.sync_push_history(manager, rid, client)
    assert monitor.run_history(rid)[0]['report_available'] is False
    client.content = artifact()
    monitor.sync_push_history(manager, rid, client)
    assert monitor.run_history(rid) == []
    assert len(manager.get_all_scans()) == 1


def test_historical_attempts_use_separate_artifact_time_windows(environment):
    manager, rid, client = environment
    old = {**client.run}
    client.run.update(run_attempt=2, run_started_at='2026-10-15T02:00:00Z')
    client.artifacts.append({'id':13, 'name':'security-reports','expired':False,'created_at':'2026-10-15T02:00:30Z'})
    original = client.get
    client.get = lambda path, params=None: old if path.endswith('/attempts/1') else original(path, params)
    result = monitor.sync_push_history(manager, rid, client)
    assert result['attempts'] == 2 and len(manager.get_all_scans()) == 2


def test_pre_upgrade_cached_allow_is_revalidated(environment):
    from contextlib import closing
    manager, rid, client = environment
    result = sync(environment)
    with closing(database.get_connection()) as connection, connection:
        row = connection.execute('SELECT metadata FROM github_imports').fetchone()
        metadata = json.loads(row['metadata'])
        metadata.pop('validation_version')
        connection.execute('UPDATE github_imports SET metadata=?', (json.dumps(metadata),))
    # A legacy parser ignored this secret, so its old ALLOW summary no longer matches.
    files = {}
    with zipfile.ZipFile(io.BytesIO(client.content)) as archive:
        files = {name: json.loads(archive.read(name)) for name in archive.namelist()}
    files['trivy.json']['Results'] = [{'Target':'config.py','Secrets':[{'RuleID':'x','Severity':'HIGH'}]}]
    content = io.BytesIO()
    with zipfile.ZipFile(content,'w') as archive:
        for name,value in files.items(): archive.writestr(name,json.dumps(value))
    client.content = content.getvalue()
    checked = sync(environment)
    assert checked['execution_status'] == 'error' and checked['policy_status'] is None
    assert monitor.run_history(rid)[0]['report_available'] is False
    # Original data is preserved for audit; never delete the user's recorded scan.
    assert manager.get_all_scans()[0]['id'] == result['scan_id']
