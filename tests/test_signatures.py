
import tempfile
import unittest
from pathlib import Path

from src.signatures import (
    generate_key_pair,
    sign_file,
    verify_signature,
)


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.root = Path(self.temp_dir.name)
        self.report = self.root / "report.json"
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        self.signature = self.root / "report.sig"

        self.report.write_text(
            '{"status": "PASS"}',
            encoding="utf-8",
        )
        generate_key_pair(self.private_key, self.public_key)

    def test_valid_signature_verifies(self):
        sign_file(self.report, self.private_key, self.signature)

        self.assertTrue(
            verify_signature(self.report, self.public_key, self.signature)
        )

    def test_modified_report_fails_verification(self):
        sign_file(self.report, self.private_key, self.signature)
        self.report.write_text(
            '{"status": "ALERT"}',
            encoding="utf-8",
        )

        self.assertFalse(
            verify_signature(self.report, self.public_key, self.signature)
        )

    def test_wrong_public_key_fails_verification(self):
        sign_file(self.report, self.private_key, self.signature)

        other_private = self.root / "other_private.pem"
        other_public = self.root / "other_public.pem"
        generate_key_pair(other_private, other_public)

        self.assertFalse(
            verify_signature(self.report, other_public, self.signature)
        )


if __name__ == "__main__":
    unittest.main()
