from pathlib import Path
import hashlib
import json

import yaml


CONFIG_PATH = (
    Path(__file__).resolve().parent.parent
    / "security-policy.yaml"
)


def load_local_policy():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    return validate_policy_config(config)


def validate_policy_config(config):
    if (not isinstance(config, dict) or not isinstance(config.get("policy"), dict)
            or type(config["policy"].get("minimum_score")) is not int
            or not 0 <= config["policy"]["minimum_score"] <= 100
            or not isinstance(config.get("severity"), dict)
            or any(str(config["severity"].get(level, "")).upper() != "BLOCK" for level in ("high", "critical"))):
        raise RuntimeError("Policy Failure: invalid security policy")
    version = config["policy"].get("version")
    if "version" in config["policy"] and (not isinstance(version, str) or not 1 <= len(version) <= 100
                                or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for c in version)):
        raise RuntimeError("Policy Failure: invalid policy version")
    return config


def local_snapshot(config):
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    return {"minimum_score": config["policy"]["minimum_score"],
            "version": config["policy"].get("version", f"central-file:{digest}"), "source": "central-file"}


def load_policy_config():
    from security.policy_source import source_config, fetch
    config = load_local_policy()
    source = source_config()
    snapshot = local_snapshot(config)
    if source:
        payload, envelope = fetch(source)
        config["policy"]["minimum_score"] = payload["minimum_score"]
        snapshot = {"minimum_score": payload["minimum_score"], "version": payload["version"], "source": "signed-https", "attestation": envelope}
    config["applied_policy"] = snapshot
    return config


def evaluate_policy(findings, score):
    config = load_policy_config()
    return evaluate_config(findings, score, config)


def evaluate_config(findings, score, config):
    """Evaluate the exact policy snapshot, including imported historical reports."""

    policy_config = config.get("policy", {})
    severity_config = config.get("severity", {})

    minimum_score = policy_config.get(
        "minimum_score",
        60,
    )

    block_severities = {
        severity.upper()
        for severity, action in severity_config.items()
        if str(action).upper() == "BLOCK"
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity in block_severities:
            return {
                "status": "BLOCK",
                "reason": (
                    f"{severity.title()} "
                    "vulnerability detected"
                ),
                "policy": config["applied_policy"],
            }

    if score < minimum_score:
        return {
            "status": "BLOCK",
            "reason": (
                "Security score is below "
                "the minimum threshold"
            ),
            "policy": config["applied_policy"],
        }

    return {
        "status": "ALLOW",
        "reason": "Security requirements passed",
        "policy": config["applied_policy"],
    }
