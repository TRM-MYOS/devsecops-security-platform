import json
from pathlib import Path

from security.policy import evaluate_policy
from security.scoring import calculate_grade, calculate_score


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_bandit(file_path):
    data = load_json(file_path)
    findings = []

    for result in data.get("results", []):
        cwe_id = result.get("issue_cwe", {}).get("id")

        findings.append(
            {
                "scanner": "Bandit",
                "category": "SAST",
                "severity": result.get(
                    "issue_severity",
                    "UNKNOWN",
                ),
                "confidence": result.get(
                    "issue_confidence",
                    "UNKNOWN",
                ),
                "file": result.get("filename"),
                "line": result.get("line_number"),
                "rule_id": result.get("test_id"),
                "message": result.get("issue_text"),
                "cwe": (
                    f"CWE-{cwe_id}"
                    if cwe_id
                    else None
                ),
            }
        )

    return findings


def parse_trivy(file_path):
    data = load_json(file_path)
    findings = []

    for result in data.get("Results", []):
        target = result.get("Target")

        for vulnerability in result.get(
            "Vulnerabilities",
            [],
        ):
            cwe_ids = vulnerability.get(
                "CweIDs",
                [],
            )

            findings.append(
                {
                    "scanner": "Trivy",
                    "category": "SCA",
                    "severity": vulnerability.get(
                        "Severity",
                        "UNKNOWN",
                    ),
                    "confidence": None,
                    "file": target,
                    "line": None,
                    "rule_id": vulnerability.get(
                        "VulnerabilityID"
                    ),
                    "message": vulnerability.get(
                        "Title"
                    ),
                    "cwe": (
                        cwe_ids[0]
                        if cwe_ids
                        else None
                    ),
                }
            )

    return findings


def parse_gitleaks(file_path):
    data = load_json(file_path)
    findings = []

    if not isinstance(data, list):
        return findings

    for result in data:
        findings.append(
            {
                "scanner": "Gitleaks",
                "category": "SECRET",
                "severity": "HIGH",
                "confidence": None,
                "file": result.get("File"),
                "line": result.get("StartLine"),
                "rule_id": result.get("RuleID"),
                "message": result.get("Description"),
                "cwe": None,
            }
        )

    return findings


def parse_reports(
    bandit_path,
    trivy_path,
    gitleaks_path=None,
):
    findings = []

    if Path(bandit_path).exists():
        findings.extend(
            parse_bandit(bandit_path)
        )

    if Path(trivy_path).exists():
        findings.extend(
            parse_trivy(trivy_path)
        )

    if (
        gitleaks_path
        and Path(gitleaks_path).exists()
    ):
        findings.extend(
            parse_gitleaks(gitleaks_path)
        )

    return findings


def build_summary(
    findings,
    score,
    grade,
    policy_result,
):
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    scanner_counts = {
        "Bandit": 0,
        "Trivy": 0,
        "Gitleaks": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        if severity not in severity_counts:
            severity = "UNKNOWN"

        severity_counts[severity] += 1

        scanner = finding.get("scanner")

        if scanner in scanner_counts:
            scanner_counts[scanner] += 1

    return {
        "status": policy_result["status"],
        "score": score,
        "grade": grade,
        "reason": policy_result["reason"],
        "findings": len(findings),
        "scanner_counts": scanner_counts,
        "severity_counts": severity_counts,
        "findings_data": findings,
    }


def save_summary(summary, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            summary,
            file,
            indent=2,
            ensure_ascii=False,
        )


def main():
    base_path = (
        Path(__file__).resolve().parent.parent
    )

    reports_dir = base_path / "reports"

    bandit_file = reports_dir / "bandit.json"
    trivy_file = reports_dir / "trivy.json"
    gitleaks_file = (
        reports_dir / "gitleaks.json"
    )

    findings = parse_reports(
        bandit_file,
        trivy_file,
        gitleaks_file,
    )

    score = calculate_score(findings)
    grade = calculate_grade(score)

    policy_result = evaluate_policy(
        findings,
        score,
    )

    summary = build_summary(
        findings,
        score,
        grade,
        policy_result,
    )

    summary_file = (
        reports_dir / "security-summary.json"
    )

    save_summary(
        summary,
        summary_file,
    )

    print("=== Security Analysis ===")
    print(f"Findings : {len(findings)}")
    print(f"Score    : {score}/100")
    print(f"Grade    : {grade}")
    print(
        f"Status   : {policy_result['status']}"
    )
    print(
        f"Reason   : {policy_result['reason']}"
    )

    print("\n=== Findings by Scanner ===")
    print(
        f"Bandit   : "
        f"{summary['scanner_counts']['Bandit']}"
    )
    print(
        f"Trivy    : "
        f"{summary['scanner_counts']['Trivy']}"
    )
    print(
        f"Gitleaks : "
        f"{summary['scanner_counts']['Gitleaks']}"
    )

    print("\n=== Findings by Severity ===")

    for severity, count in (
        summary["severity_counts"].items()
    ):
        print(
            f"{severity:<8}: {count}"
        )

    print(
        f"\nSummary  : {summary_file}"
    )

    if policy_result["status"] == "BLOCK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()