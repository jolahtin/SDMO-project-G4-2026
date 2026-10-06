from pathlib import Path 
from cryptography.fernet import Fernet, InvalidToken 

KEY_FILE = Path(__file__).resolve().parent.parent / "secret.key"  

def generate_key() -> bytes: 
    """Generate a new Fernet encryption key.""" 
    return Fernet.generate_key() 

def save_key(key: bytes) -> None: 

    """Save the encryption key to a local file.""" 

    KEY_FILE.write_bytes(key) 

def load_key() -> bytes: 
    """Load the encryption key from the local key file.""" 
    if not KEY_FILE.exists(): 
        raise FileNotFoundError( 
            f"Encryption key not found: {KEY_FILE}" 
        ) 
    return KEY_FILE.read_bytes() 

def encrypt(data: bytes, key: bytes) -> bytes: 
    """Encrypt data using Fernet.""" 
    cipher = Fernet(key) 
    return cipher.encrypt(data) 

def decrypt(data: bytes, key: bytes) -> bytes: 
    """Decrypt data using Fernet.""" 
    cipher = Fernet(key) 
    try: 
        return cipher.decrypt(data) 
    except InvalidToken as exc: 
        raise ValueError("Invalid or corrupted encrypted data") from exc
