import time
from Crypto.Cipher import ARC4

class RC4Handler:
    def __init__(self, key):
        """
        Initialize RC4 handler with a key
        Key can be 40-2048 bits (5-256 bytes)
        """
        self.key_algorithm_name = 'RC4' # <-- TAMBAHKAN INI
        self.key = key if isinstance(key, bytes) else key.encode()
    
    def encrypt(self, data):
        # ... (sisa fungsi tidak berubah) ...
        start_time = time.time()
        cipher = ARC4.new(self.key)
        ciphertext = cipher.encrypt(data)
        encryption_time = time.time() - start_time
        return ciphertext, None, encryption_time
    
    def decrypt(self, ciphertext):
        # ... (sisa fungsi tidak berubah) ...
        start_time = time.time()
        cipher = ARC4.new(self.key)
        data = cipher.decrypt(ciphertext)
        decryption_time = time.time() - start_time
        return data, decryption_time