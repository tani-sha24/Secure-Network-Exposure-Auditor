
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import InvalidToken

from src.encryption import (
    decrypt_file,
    encrypt_file,
    generate_encryption_key,
)


class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.root = Path(self.temp_dir.name)
        self.original = self.root / "report.json"
        self.key = self.root / "encryption.key"
        self.encrypted = self.root / "report.bin"
        self.decrypted = self.root / "decrypted.json"

        self.original.write_text(
            '{"status": "PASS"}',
            encoding="utf-8",
        )
        generate_encryption_key(self.key)

    def test_encrypt_and_decrypt_round_trip(self):
        encrypt_file(self.original, self.key, self.encrypted)
        decrypt_file(self.encrypted, self.key, self.decrypted)

        self.assertEqual(
            self.original.read_bytes(),
            self.decrypted.read_bytes(),
        )

    def test_modified_ciphertext_is_rejected(self):
        encrypt_file(self.original, self.key, self.encrypted)
        ciphertext = self.encrypted.read_bytes()
        self.encrypted.write_bytes(ciphertext + b"tampered")

        with self.assertRaises(InvalidToken):
            decrypt_file(self.encrypted, self.key, self.decrypted)

    def test_wrong_key_is_rejected(self):
        encrypt_file(self.original, self.key, self.encrypted)

        other_key = self.root / "other.key"
        generate_encryption_key(other_key)

        with self.assertRaises(InvalidToken):
            decrypt_file(self.encrypted, other_key, self.decrypted)


if __name__ == "__main__":
    unittest.main()
