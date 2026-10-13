import argparse
import json
from pathlib import Path

from security.policy import evaluate_policy
from security.scoring import calculate_grade, calculate_score


def load_json(file_path, scanner=None):
    scanner = scanner or Path(file_path).stem
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(
            f"Report Validation Failure: {scanner}: {file_path}: {error}"
        ) from error


def validate_report(scanner, data):
    def require(condition, reason):
        if not condition:
            raise SystemExit(f"Report Validation Failure: {scanner}: {reason}")

    def field(item, key, kind):
        require(
            isinstance(item, dict) and type(item.get(key)) is kind,
            f"{key} must be {kind.__name__}",
        )

    def optional(item, key, kind):
        if key in item:
            field(item, key, kind)

    if scanner == "Bandit":
        require(isinstance(data, dict), "report must be an object")
        field(data, "results", list)
        field(data, "errors", list)
        require(not data["errors"], "Bandit errors is not empty")
        for item in data["results"]:
            for key in (
                "filename", "test_id", "issue_text",
                "issue_severity", "issue_confidence",
            ):
                field(item, key, str)
            field(item, "line_number", int)
            for key in ("issue_severity", "issue_confidence"):
                require(
                    item[key] in {"HIGH", "MEDIUM", "LOW", "UNDEFINED"},
                    f"invalid {key}",
                )
            if "issue_cwe" in item:
                field(item, "issue_cwe", dict)
                optional(item["issue_cwe"], "id", int)
    elif scanner == "Trivy":
        require(isinstance(data, dict), "report must be an object")
        field(data, "SchemaVersion", int)
        require(data["SchemaVersion"] == 2, "unsupported SchemaVersion")
        field(data, "ArtifactName", str)
        field(data, "ArtifactType", str)
        optional(data, "Results", list)
        for item in data.get("Results", []):
            field(item, "Target", str)
            optional(item, "Vulnerabilities", list)
            for vulnerability in item.get("Vulnerabilities", []):
                field(vulnerability, "VulnerabilityID", str)
                field(vulnerability, "Severity", str)
                require(
                    vulnerability["Severity"] in {
                        "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN",
                    },
                    "invalid Severity",
                )
                optional(vulnerability, "Title", str)
                optional(vulnerability, "CweIDs", list)
                require(
                    all(isinstance(cwe, str) for cwe in vulnerability.get("CweIDs", [])),
                    "CweIDs items must be strings",
                )
    elif scanner == "Gitleaks":
        require(isinstance(data, list), "report must be a list")
        for item in data:
            for key in ("File", "RuleID", "Description"):
                field(item, key, str)
            field(item, "StartLine", int)
    else:
        require(False, "unsupported scanner")


def parse_bandit(file_path):
    data = load_json(file_path, "Bandit")
    validate_report("Bandit", data)
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
    data = load_json(file_path, "Trivy")
    validate_report("Trivy", data)
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
    data = load_json(file_path, "Gitleaks")
    validate_report("Gitleaks", data)
    findings = []

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

    findings.extend(parse_bandit(bandit_path))
    findings.extend(parse_trivy(trivy_path))
    if gitleaks_path is not None:
        findings.extend(parse_gitleaks(gitleaks_path))

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


def main(reports_dir=None):
    base_path = (
        Path(__file__).resolve().parent.parent
    )

    reports_dir = (
        Path(reports_dir) if reports_dir is not None else base_path / "reports"
    )

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
    argument_parser = argparse.ArgumentParser(description="Analyze security reports")
    argument_parser.add_argument("reports_dir", nargs="?", help="Report directory")
    main(argument_parser.parse_args().reports_dir)
