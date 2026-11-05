"""Desired global policy and signed publication; no alteration of recorded decisions."""
import base64
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import uuid

from repository.database import get_connection
from auth.service import _audit, _check_account_administrator
from security.policy_source import canonical, source_config


def current():
    from security.policy import load_local_policy, local_snapshot
    config = load_local_policy()
    initial = local_snapshot(config)
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT data FROM policy_settings WHERE id=1").fetchone()
    return json.loads(row["data"]) if row else {"minimum_score": initial["minimum_score"], "version": initial["version"], "updated_at": None}


def save(minimum, actor_id):
    if type(minimum) is not int or not 0 <= minimum <= 100:
        raise ValueError("Minimum score must be an integer from 0 to 100")
    value = {"minimum_score": minimum, "version": str(uuid.uuid4()), "updated_at": datetime.now(timezone.utc).isoformat()}
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        if actor_id is None:
            raise PermissionError("Insufficient permissions")
        _check_account_administrator(connection, actor_id)
        before = current()
        connection.execute("INSERT INTO policy_settings VALUES (1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (json.dumps(value),))
        _audit(connection, actor_id, {"id": None, "username": "Security Policy"}, "policy.updated", before, value)
    return value


def publication():
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        path = os.environ.get("DEVSECOPS_POLICY_SIGNING_KEY_PATH", "")
        if not path or not Path(path).is_absolute():
            raise ValueError()
        with Path(path).open("rb") as file:
            content = file.read(65537)
        if len(content) > 65536:
            raise ValueError()
        key = load_pem_private_key(content, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError()
        settings = current()
        now = int(time.time())
        payload = {"schema_version": 1, "version": settings["version"], "minimum_score": settings["minimum_score"],
                   "block_severities": ["CRITICAL", "HIGH"], "issued_at": now, "expires_at": now + 900}
        return {"payload": payload, "signature": base64.b64encode(key.sign(canonical(payload))).decode()}
    except Exception as error:
        raise RuntimeError("Policy publication is not configured or unavailable") from error


def status():
    settings = current()
    try:
        config = source_config()
        from security.policy_source import verify
        verify(publication(), config) if config else None
        configured = bool(config)
    except RuntimeError:
        configured = False
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT metadata FROM github_imports ORDER BY scan_id DESC").fetchall()
    applied_policies = (json.loads(row["metadata"]).get("policy") for row in rows)
    observed = any(isinstance(applied, dict) and applied.get("version") == settings["version"]
                   and applied.get("minimum_score") == settings["minimum_score"] for applied in applied_policies)
    from repository.policy_publisher import read
    published = read(settings["version"])
    activation = "observed_in_report" if observed else "awaiting_runner_report" if configured else "setup_required"
    if published and not observed:
        activation = {"merged": "published_awaiting_report", "awaiting_merge": "awaiting_merge",
                      "failed": "publish_failed", "closed": "publication_closed",
                      "superseded": "publication_superseded"}.get(published["state"], "publishing")
    return {**settings, "source_configured": configured, "runner_observed": observed,
            "activation": activation, "delivery": "signed-https" if configured else "central-repository",
            "publication": published}
