import base64

from cryptography.fernet import Fernet, InvalidToken


def fernet_key_from_shared_secret(shared_secret: bytes) -> bytes:
    if len(shared_secret) != 32:
        raise ValueError("Expected a 32-byte ML-KEM shared secret")

    return base64.urlsafe_b64encode(shared_secret)


def encrypt(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt(data: bytes, key: bytes) -> bytes:
    try:
        return Fernet(key).decrypt(data)
    except InvalidToken as exc:
        raise ValueError("Invalid or corrupted encrypted data") from exc
