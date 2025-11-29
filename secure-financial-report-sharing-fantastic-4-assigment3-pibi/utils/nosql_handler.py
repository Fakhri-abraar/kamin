# utils/nosql_handler.py
from pymongo import MongoClient
import os

# Pastikan MongoDB sudah berjalan
MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/'
client = MongoClient(MONGO_URI)
db_nosql = client['secure_file_exchange_keystore']

# Collections
keys_collection = db_nosql['user_keys']
file_keys_collection = db_nosql['file_keys']
shared_keys_collection = db_nosql['shared_keys']

def store_file_key(file_id, owner_id, encrypted_key):
    """
    Menyimpan kunci AES file yang telah dienkripsi dengan Public Key Owner.
    """
    file_keys_collection.update_one(
        {'file_id': file_id},
        {'$set': {
            'owner_id': owner_id,
            'encrypted_key': encrypted_key
        }},
        upsert=True
    )

def get_file_key(file_id, owner_id):
    """Mengambil encrypted key berdasarkan file_id dan owner_id"""
    doc = file_keys_collection.find_one({'file_id': file_id, 'owner_id': owner_id})
    return doc['encrypted_key'] if doc else None

def store_user_keys(user_id, public_key_pem, encrypted_private_key_pem):
    """Store RSA keys in NoSQL"""
    keys_collection.update_one(
        {'user_id': user_id},
        {'$set': {
            'public_key': public_key_pem,
            'private_key': encrypted_private_key_pem
        }},
        upsert=True
    )
    
def store_user_certificate(user_id, certificate_pem):
    """
    Menyimpan sertifikat X.509 pengguna ke MongoDB.
    Disimpan di dokumen yang sama dengan kunci RSA mereka.
    """
    keys_collection.update_one(
        {'user_id': user_id},
        {'$set': {
            'certificate': certificate_pem
        }},
        upsert=True
    )

def get_user_certificate(user_id):
    """
    Mengambil sertifikat X.509 pengguna.
    """
    doc = keys_collection.find_one({'user_id': user_id})
    # Kembalikan None jika sertifikat belum ada
    return doc['certificate'] if doc and 'certificate' in doc else None

# --- [FUNGSI YANG HILANG DITAMBAHKAN DI SINI] ---
def get_user_public_key(user_id):
    """Retrieve Public Key"""
    doc = keys_collection.find_one({'user_id': user_id})
    return doc['public_key'] if doc else None
# -------------------------------------------------

def store_shared_key(file_id, recipient_id, encrypted_key):
    """
    Menyimpan kunci AES yang sudah dienkripsi dengan Public Key penerima (Consultant).
    """
    shared_keys_collection.update_one(
        {'file_id': file_id, 'recipient_id': recipient_id},
        {'$set': {
            'encrypted_key': encrypted_key
        }},
        upsert=True
    )

def get_shared_key(file_id, recipient_id):
    """Mengambil shared key untuk recipient tertentu"""
    doc = shared_keys_collection.find_one({'file_id': file_id, 'recipient_id': recipient_id})
    return doc['encrypted_key'] if doc else None

def get_user_private_key_enc(user_id):
    """Mengambil Encrypted Private Key user dari MongoDB"""
    doc = keys_collection.find_one({'user_id': user_id})
    return doc['private_key'] if doc else None