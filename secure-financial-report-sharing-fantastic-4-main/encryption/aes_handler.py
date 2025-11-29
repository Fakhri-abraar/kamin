import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESHandler:
    def __init__(self, key):
        """
        Initialize AES handler with a key
        Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)
        """
        self.key_algorithm_name = 'AES' 
        self.key = key if isinstance(key, bytes) else key.encode()
        if len(self.key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
    
    def encrypt(self, data):
        start_time = time.time()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        encryption_time = time.time() - start_time
        return ciphertext, iv, encryption_time
    
    def decrypt(self, ciphertext, iv):
        start_time = time.time()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        decryption_time = time.time() - start_time
        return data, decryption_time