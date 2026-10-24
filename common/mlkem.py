from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mlkem


def generate_keypair(private_path: Path, public_path: Path) -> None:
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(private_key.private_bytes_raw())
    public_path.write_bytes(public_key.public_bytes_raw())


def load_private_key(path: Path):
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(path.read_bytes())


def load_public_key(path: Path):
    return mlkem.MLKEM768PublicKey.from_public_bytes(path.read_bytes())


def encapsulate(public_key):
    # Returns (shared_secret, KEM_ciphertext).
    return public_key.encapsulate()


def decapsulate(private_key, ciphertext: bytes) -> bytes:
    return private_key.decapsulate(ciphertext)