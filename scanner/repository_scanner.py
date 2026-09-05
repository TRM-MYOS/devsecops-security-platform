from pathlib import Path
from tempfile import TemporaryDirectory
import re
import subprocess


GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$"
)


def clone_repository(repo_url: str):
    if not GITHUB_URL_PATTERN.match(repo_url):
        raise ValueError(
            "Invalid GitHub repository URL"
        )

    temp_dir = TemporaryDirectory(
        prefix="devsecops_scan_"
    )

    repo_path = (
        Path(temp_dir.name)
        / "repository"
    )

    result = subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            repo_url,
            str(repo_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        temp_dir.cleanup()

        error_message = (
            result.stderr.strip()
            or "Git clone failed"
        )

        raise RuntimeError(
            error_message
        )

    return temp_dir, repo_path