"""Authentication and authorization contracts against an isolated database."""

import importlib
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient


PASSWORD = "Test-only-password-31!"
PUBLIC_USER_FIELDS = {
    "id", "username", "role", "is_active", "created_at", "updated_at",
}


@pytest.fixture
def auth_environment(tmp_path, monkeypatch):
    database_path = tmp_path / "auth-tests.db"
    monkeypatch.setenv("DEVSECOPS_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("DEVSECOPS_ENV", "development")
    monkeypatch.setenv("DEVSECOPS_COOKIE_SECURE", "false")
    monkeypatch.setenv("DEVSECOPS_ALLOWED_ORIGINS", "http://testserver")
    database = importlib.import_module("repository.database")
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    database.initialize_database()
    service = importlib.import_module("auth.service")
    users = {
        "superuser": service.bootstrap_superuser("admin", PASSWORD),
        "operator": service.create_user("operator", PASSWORD, "operator"),
        "viewer": service.create_user("viewer", PASSWORD, "viewer"),
    }
    api = importlib.import_module("api.app")
    repository = api.repository_manager.add_repository(
        "https://github.com/TRM-MYOS/test-auth-repository"
    )
    scan_id = api.repository_manager.save_scan(
        repository_id=repository["id"],
        scanned_at="2026-10-13T00:00:00+00:00",
        score=100,
        grade="A",
        status="ALLOW",
        reason="Security requirements passed",
        findings=[],
    )
    scan_calls = []

    def fake_scan(repository_id):
        scan_calls.append(repository_id)
        return {
            "scan_id": scan_id,
            "repository": api.repository_manager.get_repository(repository_id),
            "status": "ALLOW", "score": 100, "grade": "A",
            "reason": "Security requirements passed", "findings": 0,
            "findings_data": [],
            "scanner_counts": {"Bandit": 0, "Trivy": 0, "Gitleaks": 0},
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "scanner_results": {"bandit": 0, "trivy": 0, "gitleaks": 0},
        }

    monkeypatch.setattr(api, "execute_repository_scan", fake_scan)
    return {
        "api": api, "database": database, "service": service,
        "users": users, "repository": repository, "scan_id": scan_id,
        "scan_calls": scan_calls,
    }


def login(client, username="admin", password=PASSWORD):
    csrf = client.get("/api/auth/csrf")
    assert csrf.status_code == 200
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf.json()["csrf_token"]},
    )
    assert response.status_code == 200, response.text
    return response, {"X-CSRF-Token": response.json()["csrf_token"]}


def user_id(environment, role):
    return environment["users"][role]["id"]


def protected_requests(environment):
    repository_id = environment["repository"]["id"]
    viewer_id = user_id(environment, "viewer")
    return [
        ("GET", "/api/auth/me", None, {"viewer", "operator", "superuser"}),
        ("GET", "/api/policy", None, {"viewer", "operator", "superuser"}),
        ("GET", "/api/repositories", None, {"viewer", "operator", "superuser"}),
        ("GET", f"/api/repositories/{repository_id}", None, {"viewer", "operator", "superuser"}),
        ("GET", f"/api/repositories/{repository_id}/history", None, {"viewer", "operator", "superuser"}),
        ("GET", "/api/scans", None, {"viewer", "operator", "superuser"}),
        ("GET", f"/api/scans/{environment['scan_id']}/findings", None, {"viewer", "operator", "superuser"}),
        ("GET", "/api/users", None, {"superuser"}),
        ("GET", "/api/users/audit", None, {"superuser"}),
        ("POST", "/api/repositories", {"repo_url": "https://github.com/TRM-MYOS/new-auth-repository"}, {"operator", "superuser"}),
        ("POST", f"/api/repositories/{repository_id}/scan", None, {"operator", "superuser"}),
        ("POST", "/api/repositories/scan-all", None, {"operator", "superuser"}),
        ("POST", "/scan", {"repo_url": "https://github.com/TRM-MYOS/legacy-auth-repository"}, {"operator", "superuser"}),
        ("POST", "/api/users", {"username": "new-user", "password": PASSWORD, "role": "viewer"}, {"superuser"}),
        ("PATCH", f"/api/users/{viewer_id}", {"role": "viewer"}, {"superuser"}),
        ("DELETE", f"/api/repositories/{repository_id}", None, {"superuser"}),
        ("POST", "/api/auth/logout", None, {"viewer", "operator", "superuser"}),
    ]


def test_anonymous_cannot_access_any_protected_api(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        for method, path, payload, _ in protected_requests(auth_environment):
            response = client.request(method, path, json=payload)
            assert response.status_code == 401, (method, path, response.text)
    assert auth_environment["scan_calls"] == []


def test_authenticated_policy_endpoint_uses_config_and_scoring_sources(auth_environment, tmp_path, monkeypatch):
    from security import policy, scoring

    original_policy_path = policy.CONFIG_PATH
    original_policy_bytes = original_policy_path.read_bytes()
    temporary_policy_path = tmp_path / "test-policy.yaml"
    temporary_policy_path.write_text(
        "policy:\n  minimum_score: 75\n\n"
        "severity:\n  critical: BLOCK\n  high: BLOCK\n  medium: BLOCK\n  low: ALLOW\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(policy, "CONFIG_PATH", temporary_policy_path)
    with TestClient(auth_environment["api"].app) as client:
        login(client, "viewer")
        response = client.get("/api/policy")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["policy"] == {"minimum_score": 75}
    assert data["severity"] == {
        "critical": "BLOCK", "high": "BLOCK", "medium": "BLOCK", "low": "ALLOW",
    }
    assert data["severity_penalties"] == scoring.SEVERITY_PENALTY
    assert data["grade_bands"] == [
        {"grade": "A", "minimum_score": 90},
        {"grade": "B", "minimum_score": 80},
        {"grade": "C", "minimum_score": 70},
        {"grade": "D", "minimum_score": 60},
        {"grade": "F", "minimum_score": 0},
    ]
    assert original_policy_path.read_bytes() == original_policy_bytes


@pytest.mark.parametrize("role", ["viewer", "operator", "superuser"])
def test_every_role_is_enforced_at_api_boundary(auth_environment, role):
    username = auth_environment["users"][role]["username"]
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client, username)
        for method, path, payload, allowed_roles in protected_requests(auth_environment):
            response = client.request(method, path, json=payload, headers=headers)
            if role in allowed_roles:
                assert response.status_code in (200, 201, 204), (role, method, path, response.text)
            else:
                assert response.status_code == 403, (role, method, path, response.text)
    if role == "viewer":
        assert auth_environment["scan_calls"] == []


@pytest.mark.parametrize("role", ["viewer", "operator", "superuser"])
def test_authorized_mutations_require_csrf_and_wrong_role_is_rejected_first(auth_environment, role):
    with TestClient(auth_environment["api"].app) as client:
        login(client, auth_environment["users"][role]["username"])
        for method, path, payload, allowed_roles in protected_requests(auth_environment):
            if method == "GET":
                continue
            for headers in ({}, {"X-CSRF-Token": "forged-csrf-token"}):
                response = client.request(method, path, json=payload, headers=headers)
                assert response.status_code == 403, (role, method, path, response.text)
                if role not in allowed_roles:
                    assert "csrf" not in response.text.lower()
    assert auth_environment["scan_calls"] == []


def test_login_me_logout_and_public_user_fields(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        response, headers = login(client)
        user = response.json()["user"]
        assert set(user) == PUBLIC_USER_FIELDS
        assert user["role"] == "superuser"
        assert user["is_active"] is True
        assert "httponly" in response.headers.get("set-cookie", "").lower()
        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["user"] == user
        assert me.json()["csrf_token"] == headers["X-CSRF-Token"]
        settings = auth_environment["api"].app.state.auth_settings
        old_cookie = client.cookies.get(settings.cookie_name)
        logout = client.post("/api/auth/logout", headers=headers)
        assert logout.status_code in (200, 204)
        assert client.get("/api/auth/me").status_code == 401
        client.cookies.set(settings.cookie_name, old_cookie)
        assert client.get("/api/auth/me").status_code == 401


def test_login_rotates_anonymous_session_and_csrf(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        settings = auth_environment["api"].app.state.auth_settings
        old_csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        old_cookie = client.cookies.get(settings.cookie_name)
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD},
            headers={"X-CSRF-Token": old_csrf},
        )
        assert response.status_code == 200
        assert response.json()["csrf_token"] != old_csrf
        assert client.cookies.get(settings.cookie_name) != old_cookie
        assert auth_environment["service"].get_session(old_cookie) is None
        assert client.post("/api/auth/logout", headers={"X-CSRF-Token": old_csrf}).status_code == 403
        assert client.get("/api/auth/me").status_code == 200


def test_login_requires_csrf_and_bad_credentials_are_indistinguishable(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        response = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 403
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        wrong_password = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"}, headers=headers)
        missing_user = client.post("/api/auth/login", json={"username": "missing-user", "password": "wrong-password"}, headers=headers)
        assert wrong_password.status_code == missing_user.status_code == 401
        assert wrong_password.json() == missing_user.json()
        assert client.get("/api/auth/me").status_code == 401


def test_expired_session_cannot_be_used(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        login(client, "operator")
        with auth_environment["database"].get_connection() as connection:
            connection.execute(
                "UPDATE auth_sessions SET expires_at = ? WHERE user_id = ?",
                (time.time() - 1, user_id(auth_environment, "operator")),
            )
        assert client.get("/api/auth/me").status_code == 401
        assert client.post("/api/repositories/scan-all").status_code == 401
    assert auth_environment["scan_calls"] == []


@pytest.mark.parametrize("changes", [{"is_active": False}, {"role": "viewer"}])
def test_user_updates_revoke_existing_sessions(auth_environment, changes):
    with TestClient(auth_environment["api"].app) as admin, TestClient(auth_environment["api"].app) as operator:
        _, admin_headers = login(admin)
        _, operator_headers = login(operator, "operator")
        response = admin.patch(
            f"/api/users/{user_id(auth_environment, 'operator')}",
            json=changes, headers=admin_headers,
        )
        assert response.status_code == 200, response.text
        assert operator.get("/api/auth/me").status_code == 401
        assert operator.post("/api/repositories/scan-all", headers=operator_headers).status_code == 401
        if changes.get("is_active") is False:
            csrf = operator.get("/api/auth/csrf").json()["csrf_token"]
            response = operator.post("/api/auth/login", json={"username": "operator", "password": PASSWORD}, headers={"X-CSRF-Token": csrf})
            assert response.status_code == 401
        else:
            _, new_headers = login(operator, "operator")
            assert operator.get("/api/auth/me").json()["user"]["role"] == "viewer"
            assert operator.post("/api/repositories/scan-all", headers=new_headers).status_code == 403


def test_viewer_and_operator_cannot_elevate_their_own_privileges(auth_environment):
    for role in ("viewer", "operator"):
        with TestClient(auth_environment["api"].app) as client:
            _, headers = login(client, auth_environment["users"][role]["username"])
            response = client.patch(f"/api/users/{user_id(auth_environment, role)}", json={"role": "superuser"}, headers=headers)
            assert response.status_code == 403
            response = client.post("/api/users", json={"username": f"elevated-{role}", "password": PASSWORD, "role": "superuser"}, headers=headers)
            assert response.status_code == 403
            assert client.get("/api/auth/me").json()["user"]["role"] == role


@pytest.mark.parametrize("changes", [{"role": "viewer"}, {"role": "operator"}, {"is_active": False}])
def test_last_active_superuser_cannot_be_demoted_or_disabled(auth_environment, changes):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        response = client.patch(f"/api/users/{user_id(auth_environment, 'superuser')}", json=changes, headers=headers)
        assert response.status_code == 409, response.text
        assert client.get("/api/auth/me").json()["user"]["role"] == "superuser"
        assert client.get("/api/auth/me").json()["user"]["is_active"] is True


def test_last_superuser_guard_is_atomic_under_concurrent_updates(auth_environment):
    service = auth_environment["service"]
    second = service.create_user("second-admin", PASSWORD, "superuser")
    first_id = user_id(auth_environment, "superuser")

    def demote(target_id):
        try:
            # Exercise the storage invariant independently from actor revocation.
            # API role checks and transaction-time actor checks have separate tests.
            service.update_user(target_id, {"role": "viewer"})
            return "updated"
        except service.ConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(demote, [first_id, second["id"]]))
    assert results.count("updated") == 1, results
    conflicts = [result for result in results if isinstance(result, service.ConflictError)]
    assert len(conflicts) == 1
    assert "last active" in str(conflicts[0]).lower()
    with auth_environment["database"].get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM users WHERE role = 'superuser' AND is_active = 1").fetchone()[0]
    assert count == 1


def test_duplicate_username_is_rejected_and_audit_contains_no_secrets(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        response, headers = login(client)
        payload = {"username": "audit-user", "password": PASSWORD, "role": "viewer"}
        created = client.post("/api/users", json=payload, headers=headers)
        assert created.status_code in (200, 201), created.text
        duplicate = client.post("/api/users", json=payload, headers=headers)
        assert duplicate.status_code == 409, duplicate.text
        duplicate = client.post("/api/users", json={**payload, "username": "AUDIT-USER"}, headers=headers)
        assert duplicate.status_code == 409, duplicate.text
        users = client.get("/api/users")
        assert users.status_code == 200
        for user in users.json()["users"]:
            assert set(user) == PUBLIC_USER_FIELDS
        audit = client.get("/api/users/audit")
        assert audit.status_code == 200
        events = audit.json()["events"]
        assert events
        serialized = json.dumps(events)
        assert PASSWORD not in serialized
        assert headers["X-CSRF-Token"] not in serialized
        assert "$argon2" not in serialized
        for cookie in response.cookies.values():
            assert cookie not in serialized
        with auth_environment["database"].get_connection() as connection:
            stored_hash = connection.execute("SELECT password_hash FROM users WHERE username = ?", ("audit-user",)).fetchone()[0]
        assert stored_hash != PASSWORD
        assert stored_hash.startswith("$argon2")


def test_login_failure_rate_limit_returns_429(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        statuses = []
        for _ in range(20):
            response = client.post("/api/auth/login", json={"username": "admin", "password": "incorrect-password"}, headers={"X-CSRF-Token": csrf})
            statuses.append(response.status_code)
            if response.status_code == 429:
                break
        assert 401 in statuses
        assert statuses[-1] == 429, statuses


@pytest.mark.parametrize("origins", ["*", "https://*.example.com"])
def test_production_rejects_wildcard_cors(monkeypatch, origins):
    from auth.settings import Settings

    monkeypatch.setenv("DEVSECOPS_ENV", "production")
    monkeypatch.setenv("DEVSECOPS_COOKIE_SECURE", "true")
    monkeypatch.setenv("DEVSECOPS_ALLOWED_ORIGINS", origins)
    with pytest.raises(ValueError, match="explicit"):
        Settings.from_environment()


def test_production_requires_secure_session_cookie(monkeypatch):
    from auth.settings import Settings

    monkeypatch.setenv("DEVSECOPS_ENV", "production")
    monkeypatch.setenv("DEVSECOPS_COOKIE_SECURE", "false")
    monkeypatch.setenv("DEVSECOPS_ALLOWED_ORIGINS", "https://security.example.com")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings.from_environment()


def test_production_explicit_origin_uses_secure_cookie(monkeypatch):
    from auth.settings import Settings

    monkeypatch.setenv("DEVSECOPS_ENV", "production")
    monkeypatch.delenv("DEVSECOPS_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("DEVSECOPS_ALLOWED_ORIGINS", "https://security.example.com")
    settings = Settings.from_environment()
    assert settings.cookie_secure is True
    assert settings.allowed_origins == ("https://security.example.com",)


@pytest.mark.parametrize("token", [b"\xff", b"x" * 1024])
def test_malformed_csrf_token_is_rejected_without_server_error(auth_environment, token):
    with TestClient(auth_environment["api"].app, raise_server_exceptions=False) as client:
        login(client, "operator")
        response = client.post(
            "/api/repositories/scan-all", headers=[(b"X-CSRF-Token", token)],
        )
        assert response.status_code == 403, response.text
    assert auth_environment["scan_calls"] == []


@pytest.mark.parametrize("payload", [
    {"username": "admin", "password": "Secret-7!" * 20},
    {"password": PASSWORD},
    {"username": "admin", "password": {"sensitive": PASSWORD}},
])
def test_login_validation_errors_never_reflect_passwords(auth_environment, payload):
    with TestClient(auth_environment["api"].app) as client:
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login", json=payload, headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 422
        assert PASSWORD not in response.text
        assert "Secret-7!" not in response.text
        assert client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("payload", [
    {"username": "invalid-user", "password": "Secret-7!", "role": "viewer"},
    {"password": PASSWORD, "role": "viewer"},
    {"username": "invalid-user", "password": {"sensitive": PASSWORD}, "role": "viewer"},
])
def test_create_user_validation_errors_never_reflect_passwords(auth_environment, payload):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        response = client.post("/api/users", json=payload, headers=headers)
        assert response.status_code == 422
        assert PASSWORD not in response.text
        assert "Secret-7!" not in response.text
        assert not any(user["username"] == "invalid-user" for user in client.get("/api/users").json()["users"])


def test_account_disabled_during_password_verification_cannot_login(auth_environment, monkeypatch):
    service = auth_environment["service"]
    original_verify = service.verify_password

    def verify_then_disable(password, password_hash):
        valid = original_verify(password, password_hash)
        service.update_user(
            user_id(auth_environment, "operator"), {"is_active": False},
            actor_id=user_id(auth_environment, "superuser"),
        )
        return valid

    monkeypatch.setattr(service, "verify_password", verify_then_disable)
    with TestClient(auth_environment["api"].app) as client:
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login", json={"username": "operator", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 401
        assert client.get("/api/auth/me").status_code == 401
    with auth_environment["database"].get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?",
            (user_id(auth_environment, "operator"),),
        ).fetchone()[0]
    assert count == 0


def test_trailing_slash_and_encoded_paths_do_not_bypass_authorization(auth_environment):
    with TestClient(auth_environment["api"].app) as anonymous:
        for path in ("/api/repositories/", "/scan/", "/%61pi/repositories", "/%73can"):
            response = anonymous.request(
                "POST" if "scan" in path or "%73can" in path else "GET", path,
                json={"repo_url": "https://github.com/TRM-MYOS/encoded-path"},
            )
            assert response.status_code == 401, (path, response.text)
    with TestClient(auth_environment["api"].app) as viewer:
        _, headers = login(viewer, "viewer")
        for path in ("/api/users/", "/%61pi/users"):
            assert viewer.get(path).status_code == 403
        for path in ("/scan/", "/%73can"):
            response = viewer.post(path, json={"repo_url": "https://github.com/TRM-MYOS/encoded-path"}, headers=headers)
            assert response.status_code == 403, (path, response.text)
    assert auth_environment["scan_calls"] == []


def test_untrusted_origin_is_rejected_even_with_valid_csrf(auth_environment):
    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client, "operator")
        response = client.post(
            "/api/repositories/scan-all",
            headers={**headers, "Origin": "https://attacker.example.com"},
        )
        assert response.status_code == 403
        assert "origin" in response.text.lower()
    assert auth_environment["scan_calls"] == []


@pytest.mark.parametrize("path", [
    "/dashboard/users.html",
    "/dashboard//users.html",
    "/dashboard/users.html/",
    "/dashboard/subdirectory/../users.html",
    "/dashboard/USERS.HTML",
    "/dashboard/subdirectory%5C..%5Cusers.html",
    "/dashboard/users.html.",
    "/dashboard/users.html%20",
    "/dashboard/users.html::$DATA",
])
def test_user_management_page_cannot_bypass_role_guard_with_alternate_paths(auth_environment, path):
    with TestClient(auth_environment["api"].app) as viewer:
        login(viewer, "viewer")
        response = viewer.get(path)
        assert response.status_code in (403, 404), (path, response.text[:200])


@pytest.mark.parametrize("operation", ["create", "update"])
def test_admin_revoked_after_middleware_cannot_commit_account_changes(auth_environment, monkeypatch, operation):
    service = auth_environment["service"]
    service.create_user("replacement-admin", PASSWORD, "superuser")
    actor_id = user_id(auth_environment, "superuser")
    original_update = service.update_user

    with TestClient(auth_environment["api"].app) as client:
        _, headers = login(client)
        if operation == "create":
            original_hash = service.hash_password

            def hash_then_revoke(password):
                hashed = original_hash(password)
                original_update(actor_id, {"role": "operator"})
                return hashed

            monkeypatch.setattr(service, "hash_password", hash_then_revoke)
            response = client.post(
                "/api/users", json={"username": "forbidden-new-admin", "password": PASSWORD, "role": "superuser"},
                headers=headers,
            )
            assert not any(user["username"] == "forbidden-new-admin" for user in service.list_users())
        else:
            def revoke_before_update(target_id, changes, actor_id=None):
                if actor_id is not None:
                    original_update(actor_id, {"role": "operator"})
                return original_update(target_id, changes, actor_id=actor_id)

            monkeypatch.setattr(service, "update_user", revoke_before_update)
            response = client.patch(
                f"/api/users/{user_id(auth_environment, 'viewer')}",
                json={"is_active": False}, headers=headers,
            )
            assert service.get_user(user_id(auth_environment, "viewer"))["is_active"] is True
        assert response.status_code == 403, response.text
        assert client.get("/api/auth/me").status_code == 401
