
import tempfile
import unittest
from pathlib import Path

from src.integrity import (
    calculate_sha256,
    save_sha256,
    verify_sha256,
)


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.file_path = Path(self.temp_dir.name) / "report.json"
        self.file_path.write_text('{"status": "PASS"}', encoding="utf-8")

    def test_sha256_returns_64_hex_characters(self):
        digest = calculate_sha256(self.file_path)
        self.assertEqual(len(digest), 64)
        self.assertTrue(
            all(char in "0123456789abcdef" for char in digest)
        )

    def test_saved_checksum_verifies(self):
        checksum_path = save_sha256(self.file_path)
        self.assertTrue(verify_sha256(self.file_path, checksum_path))

    def test_modified_file_fails_verification(self):
        checksum_path = save_sha256(self.file_path)
        self.file_path.write_text('{"status": "ALERT"}', encoding="utf-8")
        self.assertFalse(verify_sha256(self.file_path, checksum_path))


if __name__ == "__main__":
    unittest.main()
