"""
Test script for encryption handlers (AES, DES, RC4)
Run this to verify your encryption/decryption works correctly
"""

import os
from encryption.aes_handler import AESHandler
from encryption.des_handler import DESHandler
from encryption.rc4_handler import RC4Handler

def test_aes():
    """Test AES-256-CBC encryption"""
    print("\n" + "="*60)
    print("Testing AES-256-CBC Encryption")
    print("="*60)
    
    # Test data
    plaintext = b"This is a secret financial report from 2024!"
    key = os.urandom(32)  # 256-bit key
    
    print(f"Original text: {plaintext.decode()}")
    print(f"Key length: {len(key)} bytes (256 bits)")
    
    # Encrypt
    handler = AESHandler(key)
    ciphertext, iv, encrypt_time = handler.encrypt(plaintext)
    print(f"Encrypted (hex): {ciphertext.hex()[:64]}...")
    print(f"IV (hex): {iv.hex()}")
    print(f"Encryption time: {encrypt_time:.6f} seconds")
    
    # Decrypt
    decrypted, decrypt_time = handler.decrypt(ciphertext, iv)
    print(f"Decrypted text: {decrypted.decode()}")
    print(f"Decryption time: {decrypt_time:.6f} seconds")
    
    # Verify
    if plaintext == decrypted:
        print("✅ AES Test PASSED! Encryption/Decryption works correctly!")
    else:
        print("❌ AES Test FAILED! Decrypted text doesn't match original!")
    
    return plaintext == decrypted

def test_des():
    """Test DES-CBC encryption"""
    print("\n" + "="*60)
    print("Testing DES-CBC Encryption")
    print("="*60)
    
    # Test data
    plaintext = b"Financial data: Revenue $1,000,000"
    key = os.urandom(8)  # 64-bit key (8 bytes)
    
    print(f"Original text: {plaintext.decode()}")
    print(f"Key length: {len(key)} bytes (64 bits)")
    
    # Encrypt
    handler = DESHandler(key)
    ciphertext, iv, encrypt_time = handler.encrypt(plaintext)
    print(f"Encrypted (hex): {ciphertext.hex()[:64]}...")
    print(f"IV (hex): {iv.hex()}")
    print(f"Encryption time: {encrypt_time:.6f} seconds")
    
    # Decrypt
    decrypted, decrypt_time = handler.decrypt(ciphertext, iv)
    print(f"Decrypted text: {decrypted.decode()}")
    print(f"Decryption time: {decrypt_time:.6f} seconds")
    
    # Verify
    if plaintext == decrypted:
        print("✅ DES Test PASSED! Encryption/Decryption works correctly!")
    else:
        print("❌ DES Test FAILED! Decrypted text doesn't match original!")
    
    return plaintext == decrypted

def test_rc4():
    """Test RC4 encryption"""
    print("\n" + "="*60)
    print("Testing RC4 Encryption")
    print("="*60)
    
    # Test data
    plaintext = b"Secret message: Q4 profit increased by 25%"
    key = os.urandom(16)  # 128-bit key
    
    print(f"Original text: {plaintext.decode()}")
    print(f"Key length: {len(key)} bytes (128 bits)")
    
    # Encrypt
    handler = RC4Handler(key)
    ciphertext, _, encrypt_time = handler.encrypt(plaintext)
    print(f"Encrypted (hex): {ciphertext.hex()[:64]}...")
    print(f"Encryption time: {encrypt_time:.6f} seconds")
    
    # Decrypt
    decrypted, decrypt_time = handler.decrypt(ciphertext)
    print(f"Decrypted text: {decrypted.decode()}")
    print(f"Decryption time: {decrypt_time:.6f} seconds")
    
    # Verify
    if plaintext == decrypted:
        print("✅ RC4 Test PASSED! Encryption/Decryption works correctly!")
    else:
        print("❌ RC4 Test FAILED! Decrypted text doesn't match original!")
    
    return plaintext == decrypted

def test_file_encryption():
    """Test file encryption/decryption"""
    print("\n" + "="*60)
    print("Testing File Encryption")
    print("="*60)
    
    # Create a test file
    test_file = "test_file.txt"
    test_content = b"This is a test financial report.\nRevenue: $500,000\nExpenses: $300,000\nProfit: $200,000"
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"Created test file: {test_file}")
    print(f"File size: {len(test_content)} bytes")
    
    # Test with AES
    key = os.urandom(32)
    handler = AESHandler(key)
    
    # Read file
    with open(test_file, 'rb') as f:
        file_data = f.read()
    
    # Encrypt
    encrypted_data, iv, _ = handler.encrypt(file_data)
    encrypted_file = "test_file_encrypted.bin"
    with open(encrypted_file, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Encrypted file saved: {encrypted_file}")
    print(f"Encrypted size: {len(encrypted_data)} bytes")
    
    # Decrypt
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data, _ = handler.decrypt(encrypted_data, iv)
    decrypted_file = "test_file_decrypted.txt"
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Decrypted file saved: {decrypted_file}")
    
    # Verify
    if test_content == decrypted_data:
        print("✅ File Encryption Test PASSED!")
    else:
        print("❌ File Encryption Test FAILED!")
    
    # Cleanup
    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)
    print("Test files cleaned up")
    
    return test_content == decrypted_data

def test_performance():
    """Test encryption performance"""
    print("\n" + "="*60)
    print("Testing Encryption Performance")
    print("="*60)
    
    import time
    
    # Test data - 1MB of data
    data_size = 1024 * 1024  # 1 MB
    plaintext = os.urandom(data_size)
    
    print(f"Test data size: {data_size / 1024:.2f} KB")
    
    # AES Performance
    aes_key = os.urandom(32)
    aes_handler = AESHandler(aes_key)
    
    start = time.time()
    aes_ciphertext, aes_iv, _ = aes_handler.encrypt(plaintext)
    aes_encrypt_time = time.time() - start
    
    start = time.time()
    aes_handler.decrypt(aes_ciphertext, aes_iv)
    aes_decrypt_time = time.time() - start
    
    print(f"AES Encryption: {aes_encrypt_time:.4f} seconds")
    print(f"AES Decryption: {aes_decrypt_time:.4f} seconds")
    print(f"AES Speed: {data_size / (1024 * 1024) / aes_encrypt_time:.2f} MB/s")
    
    # DES Performance
    des_key = os.urandom(8)
    des_handler = DESHandler(des_key)
    
    start = time.time()
    des_ciphertext, des_iv, _ = des_handler.encrypt(plaintext)
    des_encrypt_time = time.time() - start
    
    start = time.time()
    des_handler.decrypt(des_ciphertext, des_iv)
    des_decrypt_time = time.time() - start
    
    print(f"DES Encryption: {des_encrypt_time:.4f} seconds")
    print(f"DES Decryption: {des_decrypt_time:.4f} seconds")
    print(f"DES Speed: {data_size / (1024 * 1024) / des_encrypt_time:.2f} MB/s")
    
    # RC4 Performance
    rc4_key = os.urandom(16)
    rc4_handler = RC4Handler(rc4_key)
    
    start = time.time()
    rc4_ciphertext, _, _ = rc4_handler.encrypt(plaintext)
    rc4_encrypt_time = time.time() - start
    
    start = time.time()
    rc4_handler.decrypt(rc4_ciphertext)
    rc4_decrypt_time = time.time() - start
    
    print(f"RC4 Encryption: {rc4_encrypt_time:.4f} seconds")
    print(f"RC4 Decryption: {rc4_decrypt_time:.4f} seconds")
    print(f"RC4 Speed: {data_size / (1024 * 1024) / rc4_encrypt_time:.2f} MB/s")
    
    # Comparison
    print("\n📊 Performance Comparison:")
    print(f"Fastest Encryption: ", end="")
    fastest = min(aes_encrypt_time, des_encrypt_time, rc4_encrypt_time)
    if fastest == aes_encrypt_time:
        print("AES")
    elif fastest == des_encrypt_time:
        print("DES")
    else:
        print("RC4")

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🔐 ENCRYPTION HANDLERS TEST SUITE")
    print("="*60)
    
    results = []
    
    # Run tests
    try:
        results.append(("AES", test_aes()))
    except Exception as e:
        print(f"❌ AES Test Error: {e}")
        results.append(("AES", False))
    
    try:
        results.append(("DES", test_des()))
    except Exception as e:
        print(f"❌ DES Test Error: {e}")
        results.append(("DES", False))
    
    try:
        results.append(("RC4", test_rc4()))
    except Exception as e:
        print(f"❌ RC4 Test Error: {e}")
        results.append(("RC4", False))
    
    try:
        results.append(("File Encryption", test_file_encryption()))
    except Exception as e:
        print(f"❌ File Encryption Test Error: {e}")
        results.append(("File Encryption", False))
    
    try:
        test_performance()
    except Exception as e:
        print(f"❌ Performance Test Error: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{name:20s}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Your encryption handlers are working correctly!")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Please check the errors above.")

if __name__ == "__main__":
    main()
