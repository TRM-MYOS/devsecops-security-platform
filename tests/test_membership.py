"""Repository isolation and membership transitions against temporary SQLite databases."""
from contextlib import closing
from unittest.mock import Mock
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient

from test_auth import auth_environment, login
from repository import membership


@pytest.fixture
def workspace(auth_environment):
    env = auth_environment
    manager = env["api"].repository_manager
    hidden = manager.add_repository("https://github.com/TRM-MYOS/hidden-project")
    scan = manager.save_scan(hidden["id"], "2026-11-04T00:00:00Z", 75, "C", "BLOCK", "Hidden reason",
        [{"scanner": "Bandit", "file": "private.py", "line": 5, "severity": "HIGH", "message": "hidden finding"}])
    return env, hidden, scan


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_nonmembers_cannot_enumerate_or_guess_repository_and_scan_ids(workspace, role, monkeypatch):
    env, hidden, scan = workspace
    scanner = Mock(side_effect=AssertionError("Unauthorized scan"))
    monkeypatch.setattr(env["api"], "execute_repository_scan", scanner)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, role)
        for path in (f"/api/repositories/{hidden['id']}", f"/api/repositories/{hidden['id']}/history",
                     f"/api/scans/{scan}", f"/api/scans/{scan}/findings"):
            response = client.get(path)
            assert response.status_code == 404 and "hidden" not in response.text
        for path in ("/api/repositories", "/api/scans"):
            response = client.get(path)
            assert response.status_code == 200 and "hidden" not in response.text and "private.py" not in response.text
        for suffix in ("scan", "sync"):
            response = client.post(f"/api/repositories/{hidden['id']}/{suffix}", headers=csrf)
            assert response.status_code == (404 if role == "operator" else 403)
        for endpoint in ("/scan", "/api/repositories"):
            response = client.post(endpoint, json={"repo_url": hidden["url"]}, headers=csrf)
            assert response.status_code == (404 if role == "operator" else 403)
        assert client.get("/api/repositories").json()["count"] == 1
    scanner.assert_not_called()


@pytest.mark.parametrize("url", ["https://github.com/TRM-MYOS/hidden-project", "https://github.com/trm-myos/HIDDEN-PROJECT.git/", "https://github.com/TRM-MYOS/Hidden-Project/"])
def test_url_aliases_never_grant_existing_membership(workspace, url):
    env, hidden, _ = workspace
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "operator")
        assert client.post("/api/repositories", json={"repo_url": url}, headers=csrf).status_code == 404
    with closing(env["database"].get_connection()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM repository_members WHERE repository_id=?", (hidden["id"],)).fetchone()[0] == 0


def test_new_operator_repository_joins_atomically_and_leave_does_not_grant_reentry(workspace):
    env, *_ = workspace
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "operator")
        payload = {"repo_url": "https://github.com/TRM-MYOS/New-Project.git/"}
        response = client.post("/api/repositories", json=payload, headers=csrf)
        assert response.status_code == 200
        repo = response.json()["repository"]
        assert client.get(f"/api/repositories/{repo['id']}/members").json()["members"][0]["username"] == "operator"
        assert client.post("/api/repositories", json=payload, headers=csrf).json()["repository"]["id"] == repo["id"]
        assert client.post(f"/api/repositories/{repo['id']}/leave", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
        assert client.post(f"/api/repositories/{repo['id']}/leave", json={}, headers=csrf).status_code == 200
        assert client.get(f"/api/repositories/{repo['id']}").status_code == 404
        assert client.post("/api/repositories", json=payload, headers=csrf).status_code == 404
    assert env["api"].repository_manager.get_repository(repo["id"])


def test_operator_membership_management_cannot_remove_peers_or_add_admin(workspace):
    env, hidden, _ = workspace
    rid = env["repository"]["id"]
    peer = env["service"].create_user("peer-operator", "Test-password-83!", "operator")
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "operator")
        candidates = client.get(f"/api/repositories/{rid}/member-candidates?q=peer").json()["users"]
        assert candidates == [{"id": peer["id"], "username": "peer-operator", "role": "operator"}]
        assert client.post(f"/api/repositories/{rid}/members", json={"user_id": peer["id"]}, headers=csrf).status_code == 200
        assert client.delete(f"/api/repositories/{rid}/members/{peer['id']}", headers=csrf).status_code == 403
        assert client.delete(f"/api/repositories/{rid}/members/{env['users']['operator']['id']}", headers=csrf).status_code == 403
        viewer = env["users"]["viewer"]["id"]
        assert client.delete(f"/api/repositories/{rid}/members/{viewer}", headers=csrf).status_code == 200
        assert client.post(f"/api/repositories/{rid}/members", json={"user_id": env['users']['superuser']['id']}, headers=csrf).status_code == 404
        assert client.post(f"/api/repositories/{hidden['id']}/members", json={"user_id": peer['id']}, headers=csrf).status_code == 404
        assert client.get("/api/users").status_code == 403
        assert client.get("/dashboard/members.html").status_code == 200


def test_viewer_leave_is_self_only_and_immediately_revokes_access(workspace):
    env, *_ = workspace
    rid = env["repository"]["id"]
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "viewer")
        for suffix in ("members", "member-candidates"):
            assert client.get(f"/api/repositories/{rid}/{suffix}").status_code == 403
        assert client.get("/dashboard/members.html").status_code == 403
        assert client.post(f"/api/repositories/{rid}/leave", json={"user_id": env['users']['operator']['id']}, headers=csrf).status_code == 422
        assert client.post(f"/api/repositories/{rid}/leave", json={}, headers=csrf).status_code == 200
        assert client.get("/api/repositories").json()["repositories"] == []
        assert client.get("/api/scans").json()["scans"] == []
        assert client.get(f"/api/scans/{env['scan_id']}/findings").status_code == 404
    assert env["api"].repository_manager.get_all_scans()


def test_admin_bypasses_membership_but_is_never_a_member(workspace):
    env, hidden, scan = workspace
    with TestClient(env["api"].app) as client:
        _, csrf = login(client)
        assert client.get("/api/repositories").json()["count"] == 2
        assert client.get(f"/api/scans/{scan}/findings").json()["count"] == 1
        assert client.get(f"/api/repositories/{hidden['id']}/members").json() == {"members": []}
        candidates = client.get(f"/api/repositories/{hidden['id']}/member-candidates").json()["users"]
        assert {user["role"] for user in candidates} == {"operator", "viewer"}
        assert client.post(f"/api/repositories/{hidden['id']}/members", json={"user_id": env['users']['operator']['id']}, headers=csrf).status_code == 200
        assert client.delete(f"/api/repositories/{hidden['id']}/members/{env['users']['operator']['id']}", headers=csrf).status_code == 200


def test_sync_all_only_processes_visible_repositories(workspace, monkeypatch):
    env, hidden, _ = workspace
    sync = Mock(return_value={"execution_status": "waiting", "policy_status": None})
    monkeypatch.setattr(env["api"].github_monitor, "sync_all_branches", sync)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "operator")
        response = client.post("/api/github/sync", headers=csrf)
        assert response.json()["total"] == 1 and "hidden-project" not in response.text
    assert sync.call_args.args[1] == env["repository"]["id"]


def test_membership_is_rechecked_after_long_sync(workspace, monkeypatch):
    env, *_ = workspace
    rid = env["repository"]["id"]
    def sync(*args):
        membership.change(env["users"]["superuser"]["id"], rid, env["users"]["operator"]["id"], remove=True)
        return {"secret": "must-not-be-returned"}
    monkeypatch.setattr(env["api"].github_monitor, "sync_all_branches", sync)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client, "operator")
        response = client.post(f"/api/repositories/{rid}/sync", headers=csrf)
        assert response.status_code == 404 and "must-not" not in response.text


def test_promotion_disabled_accounts_and_schema_restart(workspace):
    env, *_ = workspace
    rid = env["repository"]["id"]
    operator = env["users"]["operator"]["id"]
    env["service"].update_user(operator, {"is_active": False})
    with pytest.raises(PermissionError):
        membership.change(operator, rid, env["users"]["viewer"]["id"], remove=True)
    env["service"].update_user(operator, {"is_active": True, "role": "superuser"})
    env["database"].initialize_database()
    env["database"].initialize_database()
    rows = membership.members(env["users"]["superuser"]["id"], rid)
    assert [row["role"] for row in rows] == ["viewer"]
    assert len(env["api"].repository_manager.get_all_scans()) == 2
    events = env["service"].list_audit_events()
    assert any(event["action"] == "repository.member_added" for event in events)
    assert "password_hash" not in str(events)


def test_duplicate_legacy_identity_is_not_merged(workspace):
    env, hidden, _ = workspace
    manager = env["api"].repository_manager
    manager.add_repository("https://github.com/trm-myos/HIDDEN-PROJECT.git")
    with pytest.raises(membership.Conflict):
        membership.enroll(hidden["url"], env["users"]["superuser"]["id"])
    assert len(manager.get_repositories()) == 3 and len(manager.get_all_scans()) == 2


def test_membership_survives_new_process_and_oversized_ids_are_not_errors(workspace):
    env, *_ = workspace
    process = subprocess.run([sys.executable,"-c", "from repository.database import initialize_database,get_connection; initialize_database(); c=get_connection(); print(c.execute('SELECT COUNT(*) FROM repository_members').fetchone()[0]); c.close()"],
        env={**os.environ,"DEVSECOPS_DATABASE_PATH":str(env['database'].DATABASE_PATH),"PYTHONDONTWRITEBYTECODE":"1"},capture_output=True,text=True,timeout=15)
    assert process.returncode == 0 and process.stdout.strip() == "2"
    with TestClient(env["api"].app) as client:
        login(client,"viewer")
        for path in ("/api/repositories/"+"9"*40,"/api/scans/"+"9"*40,"/api/scans/run-1-"+"9"*40+"-1"):
            assert client.get(path).status_code == 404


def test_actor_membership_is_rechecked_before_member_change(workspace, monkeypatch):
    env, *_ = workspace
    rid = env["repository"]["id"]
    candidate = env["service"].create_user("candidate", "Test-password-83!", "viewer")
    original = membership.change
    def revoked(actor_id, repository_id, target_id=None, **kwargs):
        original(env["users"]["superuser"]["id"], rid, env["users"]["operator"]["id"], remove=True)
        return original(actor_id, repository_id, target_id, **kwargs)
    monkeypatch.setattr(membership, "change", revoked)
    with TestClient(env["api"].app) as client:
        _, csrf = login(client,"operator")
        assert client.post(f"/api/repositories/{rid}/members",json={"user_id":candidate["id"]},headers=csrf).status_code == 404
    with closing(env["database"].get_connection()) as connection:
        assert connection.execute("SELECT 1 FROM repository_members WHERE user_id=?",(candidate["id"],)).fetchone() is None


def test_error_run_record_details_are_scoped_without_a_fake_score(workspace):
    import json
    env, hidden, _ = workspace
    with closing(env["database"].get_connection()) as connection, connection:
        connection.execute("INSERT INTO github_run_history VALUES (?,?,?,?,?)",(hidden["id"],999,1,None,json.dumps({"execution_status":"error","policy_status":None,"message":"Report failure","run_id":999,"run_attempt":1})))
    path=f"/api/scans/run-{hidden['id']}-999-1"
    with TestClient(env["api"].app) as client:
        login(client,"viewer")
        assert client.get(path).status_code==404
    with TestClient(env["api"].app) as client:
        login(client)
        record=client.get(path).json()["scan"]
        assert record["score"] is None and record["status"] is None and record["report_available"] is False


def test_concurrent_repository_enrollment_has_only_one_creator_membership(workspace):
    env, *_ = workspace
    peer = env["service"].create_user("concurrent-op", "Test-password-83!", "operator")
    def enroll(user):
        try:
            return membership.enroll("https://github.com/TRM-MYOS/concurrent.git", user)["id"]
        except membership.NotFound:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(enroll,[peer["id"],env["users"]["operator"]["id"]]))
    assert results.count(None) == 1
    rid = next(value for value in results if value is not None)
    assert len(membership.members(env["users"]["superuser"]["id"],rid)) == 1


def test_run_link_resolves_same_attempt_when_report_becomes_available(workspace):
    import json
    env, hidden, scan = workspace
    with closing(env["database"].get_connection()) as connection, connection:
        connection.execute("INSERT INTO github_run_history VALUES (?,?,?,?,?)",(hidden["id"],999,1,None,json.dumps({"execution_status":"running","run_id":999,"run_attempt":1})))
    path=f"/api/scans/run-{hidden['id']}-999-1"
    with TestClient(env["api"].app) as client:
        login(client)
        assert client.get(path).json()["scan"]["report_available"] is False
        with closing(env["database"].get_connection()) as connection, connection:
            connection.execute("UPDATE github_run_history SET scan_id=? WHERE run_id=999",(scan,))
        response=client.get(path)
        assert response.status_code==200 and response.json()["scan"]["id"]==scan
        assert response.json()["scan"]["status"]=="BLOCK"
