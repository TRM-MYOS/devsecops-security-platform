"""Create the first Super User without passwords in command-line arguments."""

import argparse
import getpass
import sys

from auth.service import bootstrap_superuser


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the first DevSecOps Super User")
    parser.add_argument("--username", required=True)
    arguments = parser.parse_args()
    try:
        password = getpass.getpass("Password (12–128 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match")
        user = bootstrap_superuser(arguments.username, password)
    except (ValueError, EOFError, KeyboardInterrupt) as error:
        print(f"Super User was not created: {error}", file=sys.stderr)
        return 1
    print(f"Created Super User '{user['username']}'. Sign in at /dashboard/login.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
