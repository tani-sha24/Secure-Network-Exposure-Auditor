
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def generate_encryption_key(key_path):
    """Generate and save a Fernet key."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    key = Fernet.generate_key()
    path.write_bytes(key)
    path.chmod(0o600)
    return path


def encrypt_file(file_path, key_path, output_path):
    """Encrypt a file and save the encrypted bytes."""
    key = Path(key_path).read_bytes()
    fernet = Fernet(key)

    plaintext = Path(file_path).read_bytes()
    ciphertext = fernet.encrypt(plaintext)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(ciphertext)
    return output


def decrypt_file(encrypted_path, key_path, output_path):
    """Decrypt a file; reject invalid or tampered ciphertext."""
    key = Path(key_path).read_bytes()
    fernet = Fernet(key)

    ciphertext = Path(encrypted_path).read_bytes()
    plaintext = fernet.decrypt(ciphertext)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)
    return output
