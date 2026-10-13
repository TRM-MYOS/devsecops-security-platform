from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse
import re
import subprocess


ALLOWED_OWNER = "TRM-MYOS"

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$"
)


def get_repository_owner(repo_url: str) -> str:
    """Extract repository owner from a GitHub URL."""
    parsed_url = urlparse(repo_url)
    path_parts = parsed_url.path.strip("/").split("/")

    if len(path_parts) < 2:
        raise ValueError("Invalid GitHub repository URL")

    return path_parts[0]


def validate_repository(repo_url: str):
    """Allow only repositories owned by TRM-MYOS."""

    if not GITHUB_URL_PATTERN.match(repo_url):
        raise ValueError(
            "Invalid GitHub repository URL"
        )

    owner = get_repository_owner(repo_url)

    if owner.lower() != ALLOWED_OWNER.lower():
        raise ValueError(
            f"Repository owner is not allowed. "
            f"Only repositories owned by {ALLOWED_OWNER} can be scanned."
        )


def clone_repository(repo_url: str):
    validate_repository(repo_url)

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