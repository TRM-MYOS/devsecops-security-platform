"""Persistent GitHub connection settings; never store key contents or access tokens."""

import json
import hashlib
import os
import re
import secrets
import threading
from contextlib import closing
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from repository import database


FIELDS = {
    "owner": "DEVSECOPS_GITHUB_OWNER",
    "app_id": "DEVSECOPS_GITHUB_APP_ID",
    "installation_id": "DEVSECOPS_GITHUB_INSTALLATION_ID",
    "private_key_path": "DEVSECOPS_GITHUB_PRIVATE_KEY_PATH",
    "workflow": "DEVSECOPS_GITHUB_WORKFLOW",
}
DEFAULT_OWNER = "TRM-MYOS"
DEFAULT_WORKFLOW = "security-gate-test.yml"
MAX_PRIVATE_KEY_BYTES = 64 * 1024
# Save and sync share this lock: an active round finishes before a new configuration
# is published. Nested branch/history calls reuse the same immutable-by-convention snapshot.
SETTINGS_LOCK = threading.RLock()
_snapshot = ContextVar("github_settings_snapshot", default=None)


class SettingsValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("Check the highlighted settings.")


def private_key_upload_directory():
    """Return the protected key directory used by the Owner Settings uploader."""
    configured = os.environ.get("DEVSECOPS_PRIVATE_KEY_UPLOAD_DIR", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".devsecops-security-platform" / "private-keys"


def _validate_private_key_content(content):
    if not isinstance(content, bytes) or not content or len(content) > MAX_PRIVATE_KEY_BYTES:
        raise ValueError("Key exceeds size limit")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        key = load_pem_private_key(content, password=None)
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("Unsupported signing key")
    except (ValueError, TypeError, UnsupportedAlgorithm) as error:
        raise ValueError("Cannot read a supported, unencrypted RSA private key (at least 2048 bits).") from error


def store_private_key(filename, content):
    """Validate and store an uploaded key outside the project directory."""
    original = re.split(r"[\\/]", str(filename or ""))[-1].strip()
    if not original or original.lower() in {".", ".."} or not original.lower().endswith(".pem"):
        raise SettingsValidationError({"private_key_path": "Choose an unencrypted .pem RSA private key file."})
    if any(ord(char) < 32 for char in original):
        raise SettingsValidationError({"private_key_path": "The selected filename is invalid."})
    try:
        _validate_private_key_content(content)
        directory = private_key_upload_directory()
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        path = directory / original
        if path.exists():
            path = directory / f"{path.stem}-{secrets.token_hex(8)}{path.suffix}"
        with path.open("xb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except (OSError, ValueError) as error:
        raise SettingsValidationError({"private_key_path": str(error)}) from error
    return str(path), original


def current():
    from repository.github_client import environment_configuration

    pinned = _snapshot.get()
    if pinned is not None:
        return dict(pinned)
    values = environment_configuration()
    values.setdefault(FIELDS["owner"], DEFAULT_OWNER)
    values[FIELDS["workflow"]] = values.get(FIELDS["workflow"]) or DEFAULT_WORKFLOW
    # CLI imports must not create a database merely to look up a default owner.
    if database.DATABASE_PATH.exists():
        with closing(database.get_connection()) as connection:
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='owner_settings'").fetchone():
                row = connection.execute("SELECT data FROM owner_settings WHERE id=1").fetchone()
                if row:
                    saved = json.loads(row["data"])
                    if set(saved) != set(FIELDS) or any(not isinstance(v, str) or not v for v in saved.values()):
                        raise RuntimeError("Stored GitHub settings are invalid")
                    values.update({FIELDS[field]: value for field, value in saved.items()})
    return values


def read():
    with SETTINGS_LOCK, closing(database.get_connection()) as connection:
        values = current()
        row = connection.execute("SELECT updated_at FROM owner_settings WHERE id=1").fetchone()
    settings = {field: values.get(key, "") for field, key in FIELDS.items()}
    private_key_path = settings["private_key_path"]
    # The absolute backend path is an implementation detail.  Return only the
    # filename for the authenticated UI; save/test can retain the current path
    # when the submitted field is empty.
    settings["private_key_path"] = ""
    return {"settings": settings,
            "private_key_filename": Path(private_key_path).name if private_key_path else "",
            "source": "database" if row else "environment", "updated_at": row["updated_at"] if row else None}


def fingerprint():
    values = current()
    payload = {field: values.get(key, "") for field, key in FIELDS.items()}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _audit_values(values):
    """Keep backend filesystem paths out of the administrative audit feed."""
    safe = dict(values)
    path = safe.get("private_key_path")
    if path:
        safe["private_key_path"] = Path(path).name
    return safe


def settings_scope(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with SETTINGS_LOCK:
            token = _snapshot.set(current())
            try:
                return function(*args, **kwargs)
            finally:
                _snapshot.reset(token)
    return wrapped


def validate(values):
    values = {field: value.strip() for field, value in values.items()}
    errors = {}
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", values["owner"]):
        errors["owner"] = "Use a GitHub account or organization name (1-39 letters, numbers or hyphens)."
    for field in ("app_id", "installation_id"):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", values[field]):
            errors[field] = "Enter a positive numeric ID, not a Client ID."
    if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,120}\.ya?ml", values["workflow"]):
        errors["workflow"] = "Enter only the workflow filename ending in .yml or .yaml."
    path = Path(values["private_key_path"]).expanduser()
    if not path.is_absolute() or path.suffix.lower() != ".pem" or any(c in str(path) for c in "\r\n\x00"):
        errors["private_key_path"] = "Enter an absolute .pem path on the Backend server."
    else:
        try:
            with path.open("rb") as source:
                content = source.read(MAX_PRIVATE_KEY_BYTES + 1)
            _validate_private_key_content(content)
        except (OSError, ValueError):
            errors["private_key_path"] = "Cannot read a supported, unencrypted RSA private key (at least 2048 bits)."
    if errors:
        raise SettingsValidationError(errors)
    values["private_key_path"] = str(path)
    return values


def test_connection(values):
    from repository.github_client import GitHubClient, GitHubError

    client = GitHubClient(settings={FIELDS[field]: value for field, value in values.items()})
    try:
        return client.check_connection(values["owner"])
    except GitHubError as error:
        # Only locally authored messages are used; never return GitHub response bodies.
        raise SettingsValidationError({"connection": str(error)}) from error
    finally:
        client.close()


def save(values, actor_id):
    from auth.service import _audit, _check_account_administrator

    with SETTINGS_LOCK, closing(database.get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        if actor_id is None:
            raise PermissionError("Insufficient permissions")
        _check_account_administrator(connection, actor_id)
        row = connection.execute("SELECT data FROM owner_settings WHERE id=1").fetchone()
        before = json.loads(row["data"]) if row else {field: current().get(key, "") for field, key in FIELDS.items()}
        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            "INSERT INTO owner_settings VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (json.dumps(values), now),
        )
        # Invalidate current cards atomically; historical reports/findings stay intact.
        connection.execute("UPDATE github_tracking SET data=?", (json.dumps({
            "execution_status": "not_synced", "policy_status": None, "branches": [],
            "message": "Connection settings changed. Waiting for synchronization.",
        }),))
        _audit(connection, actor_id, {"id": None, "username": "Owner Settings"},
               "owner_settings.updated", _audit_values(before), _audit_values(values))
    return read()
