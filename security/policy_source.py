"""Verify policy from a source pinned in the trusted Central checkout, never target inputs."""
import base64
import json
from pathlib import Path
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request

SOURCE_PATH = Path(__file__).resolve().parent.parent / "security-policy-source.json"


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def source_config():
    if not SOURCE_PATH.exists():
        return None
    try:
        data = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
        url = urlsplit(data["url"])
        key = base64.b64decode(data["public_key"], validate=True)
        age = data.get("maximum_age_seconds", 900)
        required = data["required_from"]
        if (url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment
                or len(key) != 32 or type(age) is not int or not 60 <= age <= 3600
                or type(required) is not int or required < 0):
            raise ValueError()
        return data
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise RuntimeError("Policy Failure: invalid trusted policy source configuration") from error


def verify(envelope, config, *, at=None):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        payload = envelope["payload"]
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(config["public_key"], validate=True))
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(payload))
        now = time.time() if at is None else at
        if (type(payload["schema_version"]) is not int or payload["schema_version"] != 1 or type(payload["minimum_score"]) is not int
                or not 0 <= payload["minimum_score"] <= 100
                or type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int
                or not payload["issued_at"] <= now + 30 or not now < payload["expires_at"]
                or not 0 < payload["expires_at"] - payload["issued_at"] <= config.get("maximum_age_seconds", 900)
                or payload["block_severities"] != ["CRITICAL", "HIGH"]
                or not isinstance(payload["version"], str) or not 1 <= len(payload["version"]) <= 100):
            raise ValueError()
        return payload
    except (KeyError, ValueError, TypeError, InvalidSignature) as error:
        raise RuntimeError("Policy Failure: invalid, expired or unauthenticated policy") from error


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(config):
    try:
        request = Request(config["url"], headers={"Accept": "application/json", "Cache-Control": "no-cache"})
        with build_opener(NoRedirect).open(request, timeout=10) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        envelope = json.loads(raw)
        return verify(envelope, config), envelope
    except Exception as error:
        raise RuntimeError("Policy Failure: cannot obtain a verified Central policy") from error
