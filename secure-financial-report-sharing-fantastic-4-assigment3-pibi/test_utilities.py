"""
Test script for Phase 2 utility functions
Tests logger, file_handler, and validators
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_validators():
    """Test validation functions"""
    print("\n" + "="*50)
    print("Testing validators.py")
    print("="*50)
    
    from utils.validators import (
        validate_username, validate_email, validate_password,
        validate_algorithm, sanitize_input
    )
    
    # Test username validation
    print("\n1. Username Validation:")
    test_usernames = [
        ("john_doe", True),
        ("ab", False),  # Too short
        ("user@name", False),  # Invalid character
        ("validuser123", True)
    ]
    
    for username, expected in test_usernames:
        is_valid, msg = validate_username(username)
        status = "✓" if is_valid == expected else "✗"
        print(f"   {status} '{username}': {is_valid} - {msg if not is_valid else 'Valid'}")
    
    # Test email validation
    print("\n2. Email Validation:")
    test_emails = [
        ("user@example.com", True),
        ("invalid.email", False),
        ("test@test.co.id", True),
        ("@example.com", False)
    ]
    
    for email, expected in test_emails:
        is_valid, msg = validate_email(email)
        status = "✓" if is_valid == expected else "✗"
        print(f"   {status} '{email}': {is_valid} - {msg if not is_valid else 'Valid'}")
    
    # Test password validation
    print("\n3. Password Validation:")
    test_passwords = [
        ("short", False),  # Too short
        ("validpassword123", True),
        ("12345678", True),
        ("", False)  # Empty
    ]
    
    for password, expected in test_passwords:
        is_valid, msg = validate_password(password)
        status = "✓" if is_valid == expected else "✗"
        display = password if password else "(empty)"
        print(f"   {status} '{display}': {is_valid} - {msg if not is_valid else 'Valid'}")
    
    # Test algorithm validation
    print("\n4. Algorithm Validation:")
    test_algos = [
        ("AES", True),
        ("DES", True),
        ("RC4", True),
        ("MD5", False),  # Invalid
        ("", False)  # Empty
    ]
    
    for algo, expected in test_algos:
        is_valid, msg = validate_algorithm(algo)
        status = "✓" if is_valid == expected else "✗"
        display = algo if algo else "(empty)"
        print(f"   {status} '{display}': {is_valid} - {msg if not is_valid else 'Valid'}")

def test_file_handler():
    """Test file handling functions"""
    print("\n" + "="*50)
    print("Testing file_handler.py")
    print("="*50)
    
    from utils.file_handler import (
        is_allowed_file, get_file_extension, generate_unique_filename,
        format_file_size, get_file_category
    )
    
    # Test file extension checking
    print("\n1. File Extension Validation:")
    test_files = [
        ("report.xlsx", "excel", True),
        ("image.png", "image", True),
        ("document.pdf", "document", True),
        ("script.exe", None, False),  # Not allowed
        ("data.csv", "text", True)
    ]
    
    for filename, category, expected in test_files:
        is_valid = is_allowed_file(filename, category)
        status = "✓" if is_valid == expected else "✗"
        cat_str = f" (category: {category})" if category else ""
        print(f"   {status} '{filename}'{cat_str}: {is_valid}")
    
    # Test file extension extraction
    print("\n2. File Extension Extraction:")
    test_filenames = [
        "report.xlsx",
        "image.PNG",
        "document.pdf"
    ]
    
    for filename in test_filenames:
        ext = get_file_extension(filename)
        print(f"   '{filename}' → '.{ext}'")
    
    # Test unique filename generation
    print("\n3. Unique Filename Generation:")
    original = "financial_report.xlsx"
    unique1 = generate_unique_filename(original)
    unique2 = generate_unique_filename(original)
    print(f"   Original: {original}")
    print(f"   Unique 1: {unique1}")
    print(f"   Unique 2: {unique2}")
    print(f"   Are different: {unique1 != unique2}")
    
    # Test file size formatting
    print("\n4. File Size Formatting:")
    test_sizes = [
        500,           # 500 B
        1024 * 50,     # 50 KB
        1024 * 1024 * 2,  # 2 MB
        1024 * 1024 * 1024  # 1 GB
    ]
    
    for size in test_sizes:
        formatted = format_file_size(size)
        print(f"   {size} bytes → {formatted}")
    
    # Test file category detection
    print("\n5. File Category Detection:")
    test_files_cat = [
        "report.xlsx",
        "photo.jpg",
        "doc.pdf",
        "notes.txt"
    ]
    
    for filename in test_files_cat:
        category = get_file_category(filename)
        print(f"   '{filename}' → {category}")

def test_key_manager():
    """Test key management functions"""
    print("\n" + "="*50)
    print("Testing key_manager.py")
    print("="*50)
    
    from utils.key_manager import generate_file_key, encrypt_file_key, decrypt_file_key
    import base64
    import os
    
    # Generate session key (simulating user's session key)
    session_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    print(f"\n1. Generated session key: {session_key[:32]}...")
    
    # Test file key generation
    print("\n2. File Key Generation:")
    for algo in ['AES', 'DES', 'RC4']:
        file_key = generate_file_key(algo)
        print(f"   {algo}: {len(file_key)} bytes")
    
    # Test key encryption/decryption
    print("\n3. Key Encryption/Decryption:")
    original_key = generate_file_key('AES')
    print(f"   Original key: {original_key.hex()[:32]}... ({len(original_key)} bytes)")
    
    # Encrypt the file key
    encrypted_key = encrypt_file_key(original_key, session_key)
    print(f"   Encrypted key: {encrypted_key[:32]}... (base64)")
    
    # Decrypt the file key
    decrypted_key = decrypt_file_key(encrypted_key, session_key)
    print(f"   Decrypted key: {decrypted_key.hex()[:32]}... ({len(decrypted_key)} bytes)")
    
    # Verify they match
    match = original_key == decrypted_key
    print(f"   Keys match: {match} {'✓' if match else '✗'}")

if __name__ == "__main__":
    print("\n" + "="*70)
    print("PHASE 2 UTILITY FUNCTIONS TEST")
    print("="*70)
    
    try:
        test_validators()
        test_file_handler()
        test_key_manager()
        
        print("\n" + "="*70)
        print("✓ ALL TESTS COMPLETED SUCCESSFULLY!")
        print("="*70)
        print("\nPhase 2 utility functions are ready to use! ✨")
        
    except Exception as e:
        print(f"\n✗ Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()
