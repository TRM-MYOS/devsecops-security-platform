"""Repository access is determined by current account role plus explicit membership."""

from contextlib import closing
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

from auth.service import _audit
from repository.database import get_connection


class NotFound(LookupError):
    pass


class Conflict(RuntimeError):
    pass


def parse_id(value):
    text = str(value)
    if not re.fullmatch(r"[0-9]{1,19}", text) or not 0 < int(text) <= 9223372036854775807:
        raise NotFound("Resource not found")
    return int(text)


def identity(url):
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or parts.netloc.casefold() != "github.com" or parts.query or parts.fragment:
        raise ValueError("Invalid GitHub repository URL")
    match = re.fullmatch(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?", parts.path)
    if not match:
        raise ValueError("Invalid GitHub repository URL")
    owner, name = match.groups()
    if name.lower().endswith(".git"):
        name = name[:-4]
    if not name or name in {".", ".."} or owner in {".", ".."}:
        raise ValueError("Invalid GitHub repository URL")
    return f"{owner}/{name}".casefold()


def actor(connection, user_id):
    user = connection.execute("SELECT id, username, role, is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if user is None or not user["is_active"]:
        raise PermissionError("Insufficient permissions")
    return user


def require(connection, user_id, repository_id, *, manage=False):
    user = actor(connection, user_id)
    repository = connection.execute("SELECT * FROM repositories WHERE id=?", (repository_id,)).fetchone()
    if repository is None:
        raise NotFound("Repository not found")
    if user["role"] != "superuser" and not connection.execute(
        "SELECT 1 FROM repository_members WHERE repository_id=? AND user_id=?", (repository_id, user_id)
    ).fetchone():
        raise NotFound("Repository not found")
    if manage and user["role"] not in {"superuser", "operator"}:
        raise PermissionError("Insufficient permissions")
    return repository, user


def check(user_id, repository_id, *, manage=False):
    with closing(get_connection()) as connection:
        return require(connection, user_id, repository_id, manage=manage)


def visible_ids(user_id):
    with closing(get_connection()) as connection:
        user = actor(connection, user_id)
        if user["role"] == "superuser":
            rows = connection.execute("SELECT id FROM repositories")
        else:
            rows = connection.execute("SELECT repository_id AS id FROM repository_members WHERE user_id=?", (user_id,))
        return {row["id"] for row in rows}


def enroll(url, user_id):
    from scanner.repository_scanner import validate_repository
    key = identity(url)
    canonical_url = f"https://github.com/{key}"
    validate_repository(canonical_url)
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        user = actor(connection, user_id)
        if user["role"] not in {"superuser", "operator"}:
            raise PermissionError("Insufficient permissions")
        matches = []
        for row in connection.execute("SELECT * FROM repositories"):
            try:
                if identity(row["url"]) == key:
                    matches.append(row)
            except ValueError:
                continue
        if matches:
            for row in matches:
                require(connection, user_id, row["id"])
            if len(matches) > 1:
                raise Conflict("Duplicate repository identities require Super User review; no data has been merged")
            return dict(matches[0])
        now = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute("INSERT INTO repositories (name,url,created_at) VALUES (?,?,?)",
                                    (key.split("/", 1)[1], canonical_url, now))
        rid = cursor.lastrowid
        if user["role"] == "operator":
            connection.execute("INSERT INTO repository_members VALUES (?,?,?,?)", (rid, user_id, now, user_id))
            _audit(connection, user_id, user, "repository.member_added", {}, {"repository_id": rid, "user_id": user_id})
        _audit(connection, user_id, {"id": None, "username": "Repository"}, "repository.created", {}, {"repository_id": rid})
        return dict(connection.execute("SELECT * FROM repositories WHERE id=?", (rid,)).fetchone())


def members(user_id, repository_id):
    with closing(get_connection()) as connection:
        require(connection, user_id, repository_id, manage=True)
        return [dict(row) for row in connection.execute(
            """SELECT u.id, u.username, u.role, u.is_active, m.joined_at
               FROM repository_members m JOIN users u ON u.id=m.user_id
               WHERE m.repository_id=? AND u.role!='superuser' ORDER BY u.username""", (repository_id,)
        )]


def candidates(user_id, repository_id, query):
    with closing(get_connection()) as connection:
        require(connection, user_id, repository_id, manage=True)
        # Literal substring search; never return hashes, sessions or administrator accounts.
        return [dict(row) for row in connection.execute(
            """SELECT id, username, role FROM users u WHERE is_active=1 AND role!='superuser'
               AND instr(lower(username), lower(?))>0
               AND NOT EXISTS (SELECT 1 FROM repository_members m WHERE m.user_id=u.id AND m.repository_id=?)
               ORDER BY username LIMIT 30""", (query.strip()[:64], repository_id)
        )]


def change(user_id, repository_id, target_id=None, *, remove=False, leave=False):
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _, user = require(connection, user_id, repository_id, manage=not leave)
        if leave:
            if user["role"] == "superuser":
                raise ValueError("Super Users access repositories without membership")
            target_id = user_id
        target_id = parse_id(target_id)
        target = connection.execute("SELECT id,username,role,is_active FROM users WHERE id=?", (target_id,)).fetchone()
        if target is None or target["role"] == "superuser":
            raise NotFound("Eligible member not found")
        exists = connection.execute("SELECT 1 FROM repository_members WHERE repository_id=? AND user_id=?",
                                    (repository_id, target_id)).fetchone()
        if remove or leave:
            if not exists:
                raise NotFound("Member not found")
            if not leave and user["role"] == "operator" and target["role"] != "viewer":
                raise PermissionError("Only a Super User can remove another Operator; use Leave for yourself")
            connection.execute("DELETE FROM repository_members WHERE repository_id=? AND user_id=?", (repository_id, target_id))
            action = "repository.member_left" if leave else "repository.member_removed"
        else:
            if not target["is_active"]:
                raise ValueError("Cannot add a disabled account")
            if exists:
                return
            connection.execute("INSERT INTO repository_members VALUES (?,?,?,?)",
                               (repository_id, target_id, datetime.now(timezone.utc).isoformat(), user_id))
            action = "repository.member_added"
        info = {"repository_id": repository_id, "user_id": target_id}
        _audit(connection, user_id, target, action, info if remove or leave else {}, {} if remove or leave else info)


def record_repository_id(record_id):
    with closing(get_connection()) as connection:
        if str(record_id).isdigit():
            row = connection.execute("SELECT repository_id FROM scans WHERE id=?", (parse_id(record_id),)).fetchone()
        else:
            match = re.fullmatch(r"run-([0-9]+)-([0-9]+)-([0-9]+)", str(record_id))
            row = connection.execute(
                "SELECT repository_id FROM github_run_history WHERE repository_id=? AND run_id=? AND attempt=?",
                tuple(map(parse_id, match.groups())),
            ).fetchone() if match else None
        if row is None:
            raise NotFound("Scan not found")
        return row["repository_id"]


def delete_repository(user_id, repository_id):
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _, user = require(connection, user_id, repository_id)
        if user["role"] != "superuser":
            raise PermissionError("Insufficient permissions")
        _audit(connection, user_id, {"id": None, "username": "Repository"}, "repository.deleted", {"repository_id": repository_id}, {})
        connection.execute("DELETE FROM repositories WHERE id=?", (repository_id,))
