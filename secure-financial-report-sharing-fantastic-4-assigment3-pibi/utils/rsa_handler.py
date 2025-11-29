# utils/rsa_handler.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# --- FUNGSI GENERATE & SERIALIZE (SUDAH ADA SEBELUMNYA) ---

def generate_key_pair():
    """Generate RSA Private & Public Key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key, password):
    """Encrypt private key with user password for storage"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

def serialize_public_key(public_key):
    """Serialize public key for storage/sharing"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# --- FUNGSI LOAD & ENCRYPT/DECRYPT (YANG HILANG/ERROR) ---

def load_private_key(pem_data, password):
    """
    Load encrypted private key from PEM format
    """
    if isinstance(password, str):
        password = password.encode()
        
    return serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )

def load_public_key(pem_data):
    """
    Load public key from PEM format
    """
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

def encrypt_with_public_key(public_key, data):
    """
    Encrypt symmetric key (or data) using RSA Public Key
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_with_private_key(private_key, ciphertext):
    """
    Decrypt symmetric key (or data) using RSA Private Key
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
def generate_self_signed_cert(private_key, public_key, username, email):
    """
    Membuat X.509 Self-Signed Certificate.
    Diperlukan agar tanda tangan PDF bisa dibaca oleh Adobe/Foxit.
    """
    # Menentukan identitas pemilik sertifikat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Fantastic 4 Secure System"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email if email else u"user@example.com"),
    ])

    # Membangun sertifikat
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Sertifikat berlaku selama 1 tahun (365 hari)
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Mengembalikan sertifikat dalam format PEM (bytes)
    return cert.public_bytes(serialization.Encoding.PEM)