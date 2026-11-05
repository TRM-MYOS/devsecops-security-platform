"""Explicit setup command: create a NEW policy-only key; never overwrite existing keys."""
import argparse
import base64
import os
from pathlib import Path


def main():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    parser = argparse.ArgumentParser(description="Create a policy signing key outside the project")
    parser.add_argument("--private-key", required=True)
    args = parser.parse_args()
    path = Path(args.private_key).expanduser().resolve()
    if path.is_relative_to(Path(__file__).resolve().parent.parent):
        parser.error("Keep the private signing key outside the project")
    key = Ed25519PrivateKey.generate()
    content = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
    except OSError:
        parser.error("Cannot create key; check the parent directory and use a new filename")
    print("Public key (copy this public value into security-policy-source.json):")
    print(base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())


if __name__ == "__main__":
    main()
