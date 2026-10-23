
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_key_pair(private_key_path, public_key_path):
    """Generate and save an Ed25519 private/public key pair."""
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)

    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def sign_file(file_path, private_key_path, signature_path):
    """Sign the exact bytes of a file using an Ed25519 private key."""
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("The supplied private key is not Ed25519")

    signature = private_key.sign(Path(file_path).read_bytes())
    Path(signature_path).write_bytes(signature)


def verify_signature(file_path, public_key_path, signature_path):
    """Return True only when the signature matches the file and public key."""
    public_key = serialization.load_pem_public_key(
        Path(public_key_path).read_bytes()
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("The supplied public key is not Ed25519")

    try:
        public_key.verify(
            Path(signature_path).read_bytes(),
            Path(file_path).read_bytes(),
        )
        return True
    except InvalidSignature:
        return False
