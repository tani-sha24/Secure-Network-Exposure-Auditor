
import argparse
import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def save_sha256(file_path):
    """Save the file's SHA-256 digest in a sidecar file."""
    path = Path(file_path)
    digest = calculate_sha256(path)
    checksum_path = Path(str(path) + ".sha256")
    checksum_path.write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
    )
    return checksum_path


def verify_sha256(file_path, checksum_path=None):
    """Compare a file's current digest with its saved digest."""
    path = Path(file_path)

    if checksum_path is None:
        checksum_path = Path(str(path) + ".sha256")
    else:
        checksum_path = Path(checksum_path)

    saved_line = checksum_path.read_text(encoding="utf-8").strip()
    saved_digest = saved_line.split()[0].lower()
    current_digest = calculate_sha256(path)

    if len(saved_digest) != 64 or any(
        char not in "0123456789abcdef" for char in saved_digest
    ):
        raise ValueError("Invalid SHA-256 checksum format")

    return current_digest == saved_digest


def main():
    parser = argparse.ArgumentParser(
        description="Calculate and verify SHA-256 report integrity."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="Hash a file")
    hash_parser.add_argument("file", help="File to hash")

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a file against its saved checksum"
    )
    verify_parser.add_argument("file", help="File to verify")
    verify_parser.add_argument(
        "--checksum",
        help="Optional path to the checksum file",
    )

    args = parser.parse_args()

    try:
        if args.command == "hash":
            checksum_path = save_sha256(args.file)
            print(f"SHA-256: {calculate_sha256(args.file)}")
            print(f"Checksum saved to: {checksum_path}")

        elif args.command == "verify":
            if verify_sha256(args.file, args.checksum):
                print("INTEGRITY OK: File matches saved SHA-256 digest.")
            else:
                print("INTEGRITY FAILED: File differs from saved digest.")
                raise SystemExit(1)

    except (OSError, ValueError, IndexError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
