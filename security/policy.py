from pathlib import Path

import yaml


CONFIG_PATH = (
    Path(__file__).resolve().parent.parent
    / "security-policy.yaml"
)


def load_policy_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def evaluate_policy(findings, score):
    config = load_policy_config()

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
            }

    if score < minimum_score:
        return {
            "status": "BLOCK",
            "reason": (
                "Security score is below "
                "the minimum threshold"
            ),
        }

    return {
        "status": "ALLOW",
        "reason": "Security requirements passed",
    }