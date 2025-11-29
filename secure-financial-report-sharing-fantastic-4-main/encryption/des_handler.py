import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

class DESHandler:
    def __init__(self, key):
        """
        Initialize DES handler with a key
        Key must be exactly 8 bytes (64 bits)
        """
        self.key_algorithm_name = 'DES' # <-- TAMBAHKAN INI
        self.key = key if isinstance(key, bytes) else key.encode()
        if len(self.key) != 8:
            self.key = (self.key[:8] if len(self.key) > 8 
                       else self.key.ljust(8, b'\0'))
    
    def encrypt(self, data):
        # ... (sisa fungsi tidak berubah) ...
        start_time = time.time()
        iv = os.urandom(8)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        padded_data = pad(data, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        encryption_time = time.time() - start_time
        return ciphertext, iv, encryption_time
    
    def decrypt(self, ciphertext, iv):
        # ... (sisa fungsi tidak berubah) ...
        start_time = time.time()
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        data = unpad(padded_data, DES.block_size)
        decryption_time = time.time() - start_time
        return data, decryption_time