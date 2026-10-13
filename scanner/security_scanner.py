import argparse
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
            "dir",
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


def validate_scanner_results(results):
    accepted_codes = {
        "bandit": {0, 1},
        "trivy": {0},
        "gitleaks": {0},
    }
    if not isinstance(results, dict):
        raise RuntimeError("Scanner Failure: results must be a dictionary")
    missing = set(accepted_codes) - set(results)
    if missing:
        raise RuntimeError(f"Scanner Failure: missing results: {', '.join(sorted(missing))}")
    for scanner, codes in accepted_codes.items():
        result = results[scanner]
        if not isinstance(result, dict):
            raise RuntimeError(f"Scanner Failure: {scanner}: invalid result")
        returncode = result.get("returncode")
        if type(returncode) is not int or returncode not in codes:
            reason = result.get("stderr") or result.get("stdout") or "no diagnostic output"
            raise RuntimeError(
                f"Scanner Failure: {scanner}: returncode={returncode}: {reason}"
            )


def run_security_scan(target_path, reports_path):
    target_path = Path(target_path).resolve()
    reports_path = Path(reports_path).resolve()

    reports_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Remove only known outputs before any scanner starts; never reuse old reports.
    for filename in (
        "bandit.json", "trivy.json", "gitleaks.json", "security-summary.json",
    ):
        report_path = reports_path / filename
        try:
            report_path.unlink(missing_ok=True)
        except OSError as error:
            raise RuntimeError(f"Scanner Failure: cannot remove {report_path}: {error}") from error

    if not target_path.is_dir():
        raise RuntimeError(f"Scanner Failure: target is not a directory: {target_path}")

    results = {}

    for scanner, run_scanner in (
        ("bandit", run_bandit),
        ("trivy", run_trivy),
        ("gitleaks", run_gitleaks),
    ):
        try:
            results[scanner] = run_scanner(target_path, reports_path / f"{scanner}.json")
        except OSError as error:
            raise RuntimeError(f"Scanner Failure: {scanner}: {error}") from error

    validate_scanner_results(results)

    return results


def main(argv=None):
    argument_parser = argparse.ArgumentParser(description="Run the Central Security Gate")
    argument_parser.add_argument("target_dir", help="Target repository directory")
    argument_parser.add_argument("reports_dir", help="Report output directory")
    arguments = argument_parser.parse_args(argv)
    try:
        results = run_security_scan(arguments.target_dir, arguments.reports_dir)
        validate_scanner_results(results)
        from security.parser import main as analyze_reports

        analyze_reports(arguments.reports_dir)
    except (OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
