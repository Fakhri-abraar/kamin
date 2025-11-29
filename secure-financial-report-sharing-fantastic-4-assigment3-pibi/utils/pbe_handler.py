import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Kita kurangi iterasi agar tidak terlalu lambat saat upload/download,
# 100,000 masih angka yang aman untuk ini.
PBKDF_ITERATIONS = 100000

def get_key_length(algorithm):
    """Mendapatkan panjang kunci yang benar dalam byte."""
    if algorithm.upper() == 'AES':
        return 32  # 256 bits
    elif algorithm.upper() == 'DES':
        return 8   # 64 bits
    elif algorithm.upper() == 'RC4':
        return 16  # 128 bits
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

def derive_key_from_password(password, salt, algorithm):
    """
    Menghasilkan kunci enkripsi yang kuat dari kata sandi menggunakan PBKDF2.
    """
    if not isinstance(password, bytes):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    key_length = get_key_length(algorithm)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
        backend=default_backend()
    )
    
    # Menghasilkan kunci
    file_key = kdf.derive(password_bytes)
    return file_key