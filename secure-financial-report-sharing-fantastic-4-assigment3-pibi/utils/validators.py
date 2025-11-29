# validators.py

"""
Utility functions for input validation
Validates user inputs, filenames, and other data
"""
import re
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest # <-- IMPOR BARU

# Konstanta untuk panjang minimal password enkripsi
MIN_ENCRYPTION_PASSWORD_LENGTH = 8 # <-- KONSTANTA BARU

def validate_username(username):
    """
    Validate username format
    """
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, None

def validate_email(email):
    """
    Validate email format
    """
    if not email:
        return False, "Email is required"
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"
    if len(email) > 120:
        return False, "Email must be less than 120 characters"
    return True, None

def validate_password(password):
    """
    Validate password strength
    """
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    return True, None

# --- FUNGSI VALIDASI BARU ---
def validate_encryption_password_length(password: str):
    """
    Memastikan panjang password untuk enkripsi minimal 8 karakter.
    Menggunakan BadRequest untuk penanganan error rute yang lebih mudah.
    """
    if len(password) < MIN_ENCRYPTION_PASSWORD_LENGTH:
        raise BadRequest(
            f"Password enkripsi harus minimal {MIN_ENCRYPTION_PASSWORD_LENGTH} karakter."
        )
    return True
# --- AKHIR FUNGSI VALIDASI BARU ---

def validate_filename(filename):
    """
    Validate and sanitize filename
    """
    if not filename:
        return False, None, "Filename is required"
    sanitized = secure_filename(filename)
    if not sanitized:
        return False, None, "Invalid filename"
    if len(sanitized) > 255:
        return False, None, "Filename is too long"
    if '.' not in sanitized:
        return False, None, "File must have an extension"
    return True, sanitized, None

def validate_algorithm(algorithm):
    """
    Validate encryption algorithm choice
    """
    valid_algorithms = ['AES', 'DES', 'RC4']
    if not algorithm:
        return False, "Algorithm is required"
    if algorithm.upper() not in valid_algorithms:
        return False, f"Invalid algorithm. Must be one of: {', '.join(valid_algorithms)}"
    return True, None

def validate_file_type(filename, allowed_types):
    """
    Validate file type against allowed types
    """
    if not filename or '.' not in filename:
        return False, "Invalid filename"
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_types:
        return False, f"File type .{ext} is not allowed. Allowed types: {', '.join(allowed_types)}"
    return True, None

def sanitize_input(text, max_length=None):
    """
    Sanitize text input by removing potentially dangerous characters
    """
    if not text:
        return ""
    sanitized = text.replace('\0', '')
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized.strip()

def validate_positive_integer(value, field_name="Value"):
    """
    Validate that a value is a positive integer
    """
    try:
        num = int(value)
        if num <= 0:
            return False, f"{field_name} must be a positive number"
        return True, None
    except (ValueError, TypeError):
        return False, f"{field_name} must be a valid number"

def validate_permission_level(permission):
    """
    Validate file sharing permission level
    """
    valid_permissions = ['view', 'download']
    if not permission:
        return False, "Permission level is required"
    if permission.lower() not in valid_permissions:
        return False, f"Invalid permission. Must be one of: {', '.join(valid_permissions)}"
    return True, None