import pytest
from common.crypto import generate_key, encrypt, decrypt

def test_encrypt_decrypt_success():
    key = generate_key()
    original_data = b"Salainen audiodata 12345"
    
    encrypted = encrypt(original_data, key)
    assert encrypted != original_data  # Datan pitää muuttua
    
    decrypted = decrypt(encrypted, key)
    assert decrypted == original_data

def test_decrypt_with_wrong_key():
    key1 = generate_key()
    key2 = generate_key()
    data = b"Testidataa"
    
    encrypted = encrypt(data, key1)
    
    with pytest.raises(ValueError, match="Invalid or corrupted encrypted data"):
        decrypt(encrypted, key2)

def test_decrypt_tampered_data():
    key = generate_key()
    encrypted = bytearray(encrypt(b"Testidataa", key))
    
    
    encrypted[10] ^= 0xFF
    
    with pytest.raises(ValueError):
        decrypt(bytes(encrypted), key)