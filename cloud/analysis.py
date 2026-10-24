import hashlib
from pathlib import Path


def analyze_data(encrypted_path: Path, decrypted_path: Path) -> dict:
    encrypted = encrypted_path.read_bytes()
    decrypted = decrypted_path.read_bytes()

    if not decrypted:
        raise ValueError("Cannot analyze empty data")

    return {
        "encrypted_bytes": len(encrypted),
        "decrypted_bytes": len(decrypted),
        "encrypted_sha256": hashlib.sha256(encrypted).hexdigest(),
        "decrypted_sha256": hashlib.sha256(decrypted).hexdigest(),
        "byte_min": min(decrypted),
        "byte_max": max(decrypted),
        "byte_average": sum(decrypted) / len(decrypted),
    }