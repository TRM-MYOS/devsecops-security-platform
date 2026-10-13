"""SQLite account storage, auditable account changes and revocable sessions."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone

from auth.passwords import PASSWORD_HASHER, hash_password, verify_password
from repository.database import get_connection, initialize_database


ROLES = frozenset({"superuser", "operator", "viewer"})
_USER_FIELDS = ("id", "username", "role", "is_active", "created_at", "updated_at")


class ConflictError(ValueError):
    """A requested change conflicts with account invariants."""


class RateLimitError(ValueError):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__("Too many login attempts. Please try again later.")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def public_user(row) -> dict:
    result = {field: row[field] for field in _USER_FIELDS}
    result["is_active"] = bool(result["is_active"])
    return result


def normalize_username(username: str) -> str:
    return username.strip().lower()


def _validate_username(username: str) -> str:
    username = normalize_username(username)
    if not re.fullmatch(r"[a-z0-9_.-]{3,64}", username):
        raise ValueError("Username must contain 3–64 letters, numbers, underscores, dots or hyphens")
    return username


def _audit(connection, actor_id, target, action, before, after):
    actor = connection.execute("SELECT username FROM users WHERE id = ?", (actor_id,)).fetchone()
    connection.execute(
        """INSERT INTO auth_audit_events
           (actor_id, actor_username, target_id, target_username, action, changes, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            actor_id,
            actor["username"] if actor else "bootstrap",
            target["id"],
            target["username"],
            action,
            json.dumps({"before": before, "after": after}),
            _timestamp(),
        ),
    )


def _check_account_administrator(connection, actor_id):
    if actor_id is None:
        # Internal callers (including first-account bootstrap) do not use HTTP sessions.
        return
    actor = connection.execute(
        "SELECT role, is_active FROM users WHERE id = ?", (actor_id,)
    ).fetchone()
    if actor is None or not actor["is_active"] or actor["role"] != "superuser":
        raise PermissionError("Insufficient permissions")


def create_user(username: str, password: str, role: str, actor_id: int | None = None,
                *, first_superuser: bool = False) -> dict:
    username = _validate_username(username)
    if role not in ROLES:
        raise ValueError("Unknown user role")
    password_hash = hash_password(password)
    now = _timestamp()
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _check_account_administrator(connection, actor_id)
        if first_superuser:
            if role != "superuser":
                raise ValueError("The first account must be a Super User")
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise ConflictError("Accounts already exist; use User Management to create another account")
        try:
            cursor = connection.execute(
                """INSERT INTO users (username, password_hash, role, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (username, password_hash, role, now, now),
            )
        except sqlite3.IntegrityError as error:
            raise ConflictError("Username already exists") from error
        user = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        _audit(
            connection, actor_id, user,
            "user.bootstrap" if first_superuser else "user.created",
            {}, {"username": username, "role": role, "is_active": True},
        )
        return public_user(user)


def bootstrap_superuser(username: str, password: str) -> dict:
    initialize_database()
    return create_user(username, password, "superuser", first_superuser=True)


def get_user(user_id: int) -> dict | None:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return public_user(row) if row else None


def list_users() -> list[dict]:
    with closing(get_connection()) as connection:
        return [public_user(row) for row in connection.execute("SELECT * FROM users ORDER BY username")]


def update_user(user_id: int, changes: dict, actor_id: int | None = None) -> dict | None:
    if not changes or set(changes) - {"role", "is_active"}:
        raise ValueError("Supply role or is_active to update a user")
    if "role" in changes and changes["role"] not in ROLES:
        raise ValueError("Unknown user role")
    if "is_active" in changes and not isinstance(changes["is_active"], bool):
        raise ValueError("is_active must be a boolean")
    # Serializing writers makes the last-active-superuser safeguard atomic.
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _check_account_administrator(connection, actor_id)
        existing = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if existing is None:
            return None
        role = changes.get("role", existing["role"])
        is_active = changes.get("is_active", bool(existing["is_active"]))
        before = {"role": existing["role"], "is_active": bool(existing["is_active"])}
        after = {"role": role, "is_active": is_active}
        if before == after:
            return public_user(existing)
        if existing["role"] == "superuser" and existing["is_active"] and (
            role != "superuser" or not is_active
        ):
            other_superuser = connection.execute(
                "SELECT 1 FROM users WHERE role = 'superuser' AND is_active = 1 AND id != ? LIMIT 1",
                (user_id,),
            ).fetchone()
            if other_superuser is None:
                raise ConflictError("Cannot disable or demote the last active Super User")
        connection.execute(
            "UPDATE users SET role = ?, is_active = ?, updated_at = ? WHERE id = ?",
            (role, int(is_active), _timestamp(), user_id),
        )
        connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        updated = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        _audit(connection, actor_id, updated, "user.updated", before, after)
        return public_user(updated)


def list_audit_events(limit: int = 200) -> list[dict]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM auth_audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event.update(json.loads(event.pop("changes")))
            events.append(event)
        return events


def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int | None = None, ttl_seconds: int = 28800,
                   replacing_token: str | None = None) -> dict:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = time.time()
    expires_at = now + ttl_seconds
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
        if replacing_token:
            connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?", (session_token_hash(replacing_token),)
            )
        if user_id is not None:
            active_user = connection.execute(
                "SELECT 1 FROM users WHERE id = ? AND is_active = 1", (user_id,)
            ).fetchone()
            if active_user is None:
                raise ValueError("Account is unavailable")
        connection.execute(
            """INSERT INTO auth_sessions (token_hash, user_id, csrf_token, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (session_token_hash(token), user_id, csrf_token, now, expires_at),
        )
    return {"token": token, "csrf_token": csrf_token, "expires_at": expires_at, "user_id": user_id}


def get_session(token: str | None) -> dict | None:
    if not token or len(token) > 128:
        return None
    token_hash = session_token_hash(token)
    with closing(get_connection()) as connection, connection:
        row = connection.execute(
            "SELECT * FROM auth_sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= time.time():
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
            return None
        session = dict(row)
        session["user"] = None
        if row["user_id"] is not None:
            user = connection.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
            if user is None or not user["is_active"]:
                connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
                return None
            session["user"] = public_user(user)
        return session


def revoke_session(token: str | None):
    if token:
        with closing(get_connection()) as connection, connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?", (session_token_hash(token),)
            )


def valid_csrf(session: dict | None, token: str | None) -> bool:
    return bool(
        session and token and len(token) <= 128
        and hmac.compare_digest(session["csrf_token"].encode(), token.encode())
    )


def authenticate(username: str, password: str, peer_ip: str,
                 max_attempts: int = 5, window_seconds: int = 900) -> dict | None:
    username = normalize_username(username)
    now = time.time()
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM auth_login_attempts WHERE attempted_at <= ?", (now - window_seconds,)
        )
        attempts = connection.execute(
            """SELECT attempted_at FROM auth_login_attempts
               WHERE username = ? OR peer_ip = ? ORDER BY attempted_at ASC""",
            (username, peer_ip),
        ).fetchall()
        if len(attempts) >= max_attempts:
            retry_after = max(1, int(attempts[0]["attempted_at"] + window_seconds - now) + 1)
            raise RateLimitError(retry_after)
        # Reserve before verification so concurrent requests cannot evade the limit.
        attempt_id = connection.execute(
            "INSERT INTO auth_login_attempts (username, peer_ip, attempted_at) VALUES (?, ?, ?)",
            (username, peer_ip, now),
        ).lastrowid
        row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    valid = verify_password(password, row["password_hash"] if row else None)
    if not valid or not row or not row["is_active"]:
        return None
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
        if current is None or not current["is_active"] or current["password_hash"] != row["password_hash"]:
            return None
        connection.execute(
            "DELETE FROM auth_login_attempts WHERE username = ? AND peer_ip = ? AND id <= ?",
            (username, peer_ip, attempt_id),
        )
        if PASSWORD_HASHER.check_needs_rehash(current["password_hash"]):
            connection.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (hash_password(password), _timestamp(), current["id"]),
            )
        return public_user(current)
