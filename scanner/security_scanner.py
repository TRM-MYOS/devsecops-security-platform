import subprocess
from pathlib import Path


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_bandit(target_path, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return run_command(
        [
            "bandit",
            "-r",
            str(target_path),
            "-f",
            "json",
            "-o",
            str(output_path),
        ]
    )


def run_trivy(target_path, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return run_command(
        [
            "trivy",
            "fs",
            "--format",
            "json",
            "--output",
            str(output_path),
            str(target_path),
        ]
    )


def run_gitleaks(target_path, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return run_command(
        [
            "gitleaks",
            "detect",
            "--source",
            str(target_path),
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(output_path),
            "--exit-code",
            "0",
        ]
    )


def run_security_scan(target_path, reports_path):
    target_path = Path(target_path).resolve()
    reports_path = Path(reports_path).resolve()

    reports_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = {}

    results["bandit"] = run_bandit(
        target_path,
        reports_path / "bandit.json",
    )

    results["trivy"] = run_trivy(
        target_path,
        reports_path / "trivy.json",
    )

    results["gitleaks"] = run_gitleaks(
        target_path,
        reports_path / "gitleaks.json",
    )

    return results