"""
Test session key and key management
"""
import os
import base64
from utils.key_manager import encrypt_file_key, decrypt_file_key, generate_file_key

def test_key_encryption():
    """Test encrypting and decrypting file keys with session key"""
    print("\n" + "="*60)
    print("Testing Session Key & Key Management")
    print("="*60)
    
    # Simulate user's session key (normally generated at login)
    session_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    print(f"Session Key (base64): {session_key[:40]}...")
    
    # Test with different algorithms
    for algorithm in ['AES', 'DES', 'RC4']:
        print(f"\n--- Testing {algorithm} ---")
        
        # Generate file encryption key
        file_key = generate_file_key(algorithm)
        print(f"Generated {algorithm} key: {len(file_key)} bytes")
        print(f"File key (hex): {file_key.hex()}")
        
        # Encrypt the file key with session key
        encrypted_key = encrypt_file_key(file_key, session_key)
        print(f"Encrypted key (base64): {encrypted_key[:40]}...")
        
        # Decrypt the file key
        decrypted_key = decrypt_file_key(encrypted_key, session_key)
        print(f"Decrypted key (hex): {decrypted_key.hex()}")
        
        # Verify
        if file_key == decrypted_key:
            print(f"✅ {algorithm} key encryption/decryption works!")
        else:
            print(f"❌ {algorithm} key encryption/decryption FAILED!")
            return False
    
    return True

def test_workflow():
    """Simulate the actual workflow"""
    print("\n" + "="*60)
    print("Simulating Real Workflow")
    print("="*60)
    
    # Step 1: User logs in, session key is generated
    print("\n1️⃣ User logs in → Generate session key")
    user_session_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    print(f"   Session key stored in database: {user_session_key[:40]}...")
    
    # Step 2: User uploads a file
    print("\n2️⃣ User uploads file")
    file_data = b"Secret financial report: Revenue $1,000,000"
    print(f"   File content: {file_data.decode()}")
    
    # Step 3: Generate random file encryption key
    print("\n3️⃣ Generate random AES key for this file")
    file_encryption_key = generate_file_key('AES')
    print(f"   File encryption key (32 bytes): {file_encryption_key.hex()}")
    
    # Step 4: Encrypt the file with the file key
    print("\n4️⃣ Encrypt file with AES key")
    from encryption.aes_handler import AESHandler
    aes = AESHandler(file_encryption_key)
    encrypted_file, iv, _ = aes.encrypt(file_data)
    print(f"   Encrypted file size: {len(encrypted_file)} bytes")
    print(f"   IV: {iv.hex()}")
    
    # Step 5: Encrypt the file key with session key
    print("\n5️⃣ Encrypt file key with session key")
    encrypted_file_key = encrypt_file_key(file_encryption_key, user_session_key)
    print(f"   Encrypted key to store: {encrypted_file_key[:40]}...")
    
    # Step 6: Store in database
    print("\n6️⃣ Store in database:")
    print(f"   - Encrypted file: {len(encrypted_file)} bytes")
    print(f"   - IV: {iv.hex()}")
    print(f"   - Encrypted file key: {encrypted_file_key[:40]}...")
    print(f"   ✅ File key is NOT stored in plaintext!")
    
    # Step 7: User wants to download/decrypt
    print("\n7️⃣ User wants to download → Decrypt")
    
    # Step 8: Decrypt file key using session key
    print("\n8️⃣ Decrypt file key using session key")
    decrypted_file_key = decrypt_file_key(encrypted_file_key, user_session_key)
    print(f"   Decrypted file key: {decrypted_file_key.hex()}")
    
    # Step 9: Decrypt file using file key
    print("\n9️⃣ Decrypt file using file key")
    aes2 = AESHandler(decrypted_file_key)
    decrypted_file, _ = aes2.decrypt(encrypted_file, iv)
    print(f"   Decrypted content: {decrypted_file.decode()}")
    
    # Verify
    print("\n🔍 Verification:")
    if file_data == decrypted_file:
        print("   ✅ Original file = Decrypted file")
        print("   ✅ Workflow successful!")
        return True
    else:
        print("   ❌ Files don't match!")
        return False

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔐 SESSION KEY & KEY MANAGEMENT TEST")
    print("="*60)
    
    # Test key encryption
    test1 = test_key_encryption()
    
    # Test full workflow
    test2 = test_workflow()
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    print(f"Key Encryption Test: {'✅ PASSED' if test1 else '❌ FAILED'}")
    print(f"Workflow Test: {'✅ PASSED' if test2 else '❌ FAILED'}")
    
    if test1 and test2:
        print("\n🎉 All tests passed! Session key management works correctly!")
    else:
        print("\n⚠️ Some tests failed!")
