SEVERITY_PENALTY = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
    "UNKNOWN": 0,
}


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = str(
            finding.get("severity", "UNKNOWN")
        ).upper()

        penalty = SEVERITY_PENALTY.get(severity, 0)
        score -= penalty

    return max(score, 0)


def calculate_grade(score):
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"