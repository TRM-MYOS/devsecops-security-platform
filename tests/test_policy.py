import pytest

from security.policy import evaluate_policy
from security.scoring import calculate_grade, calculate_score


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "high"])
def test_blocking_severity_overrides_a_passing_score(severity):
    assert evaluate_policy([{"severity": severity}], 100)["status"] == "BLOCK"


def test_medium_findings_can_block_by_accumulated_score():
    findings = [{"severity": "MEDIUM"}] * 3
    score = calculate_score(findings)
    assert score == 55
    assert calculate_grade(score) == "F"
    assert evaluate_policy(findings, score)["status"] == "BLOCK"


def test_score_threshold_and_empty_scan_keep_original_policy():
    assert evaluate_policy([], 59)["status"] == "BLOCK"
    assert evaluate_policy([], 60)["status"] == "ALLOW"
    assert calculate_score([]) == 100
    assert evaluate_policy([], 100)["status"] == "ALLOW"
    assert calculate_score([{"severity": "CRITICAL"}] * 3) == 0


@pytest.mark.parametrize("score,grade", [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"), (69, "D"), (60, "D"), (59, "F"), (0, "F")])
def test_grade_boundaries(score, grade):
    assert calculate_grade(score) == grade
