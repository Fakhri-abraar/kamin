"""
Utility functions for key management
Handles encryption/decryption of file encryption keys using user session keys
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_file_key(file_key, session_key):
    """
    Encrypt a file encryption key using the user's session key
    
    Args:
        file_key (bytes): The encryption key used for the file
        session_key (str): User's session key (base64 encoded)
    
    Returns:
        str: Base64 encoded encrypted key with IV prepended
    """
    # Decode session key from base64
    session_key_bytes = base64.b64decode(session_key)
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Create AES cipher
    cipher = Cipher(
        algorithms.AES(session_key_bytes),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad the file key
    padder = padding.PKCS7(128).padder()
    padded_key = padder.update(file_key) + padder.finalize()
    
    # Encrypt
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
    
    # Combine IV + encrypted_key and encode as base64
    combined = iv + encrypted_key
    return base64.b64encode(combined).decode('utf-8')

def decrypt_file_key(encrypted_key, session_key):
    """
    Decrypt a file encryption key using the user's session key
    
    Args:
        encrypted_key (str): Base64 encoded encrypted key with IV prepended
        session_key (str): User's session key (base64 encoded)
    
    Returns:
        bytes: The decrypted file encryption key
    """
    # Decode session key from base64
    session_key_bytes = base64.b64decode(session_key)
    
    # Decode the encrypted key from base64
    combined = base64.b64decode(encrypted_key)
    
    # Split IV and encrypted key
    iv = combined[:16]
    encrypted_key_bytes = combined[16:]
    
    # Create AES cipher
    cipher = Cipher(
        algorithms.AES(session_key_bytes),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_key = decryptor.update(encrypted_key_bytes) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    file_key = unpadder.update(padded_key) + unpadder.finalize()
    
    return file_key

def generate_file_key(algorithm):
    """
    Generate a random encryption key based on algorithm
    
    Args:
        algorithm (str): 'AES', 'DES', or 'RC4'
    
    Returns:
        bytes: Random key of appropriate length
    """
    if algorithm.upper() == 'AES':
        return os.urandom(32)  # 256 bits
    elif algorithm.upper() == 'DES':
        return os.urandom(8)   # 64 bits
    elif algorithm.upper() == 'RC4':
        return os.urandom(16)  # 128 bits

    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
