"""
Utility functions for file handling
Handles file operations, path management, and file metadata
"""
import os
import uuid
from werkzeug.utils import secure_filename
from config import Config

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'excel': {'xlsx', 'xls'},
    'image': {'png', 'jpg', 'jpeg', 'gif', 'bmp'},
    'document': {'pdf', 'doc', 'docx'},
    'text': {'txt', 'csv'}
}

def get_all_allowed_extensions():
    """Get set of all allowed extensions"""
    extensions = set()
    for category in ALLOWED_EXTENSIONS.values():
        extensions.update(category)
    return extensions

def is_allowed_file(filename, category=None):
    """
    Check if file extension is allowed
    
    Args:
        filename (str): Name of the file
        category (str, optional): Specific category to check ('excel', 'image', etc.)
                                 If None, checks all categories
    
    Returns:
        bool: True if file is allowed
    """
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if category:
        return ext in ALLOWED_EXTENSIONS.get(category, set())
    else:
        return ext in get_all_allowed_extensions()

def get_file_extension(filename):
    """
    Get the file extension
    
    Args:
        filename (str): Name of the file
    
    Returns:
        str: File extension (lowercase) or empty string
    """
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower()
    return ''

def generate_unique_filename(original_filename):
    """
    Generate a unique filename using UUID while preserving extension
    
    Args:
        original_filename (str): Original filename
    
    Returns:
        str: Unique filename with original extension
    """
    ext = get_file_extension(original_filename)
    unique_name = str(uuid.uuid4())
    
    if ext:
        return f"{unique_name}.{ext}"
    return unique_name

def get_file_size(file_obj):
    """
    Get size of uploaded file in bytes
    
    Args:
        file_obj: FileStorage object from Flask
    
    Returns:
        int: File size in bytes
    """
    # Save current position
    current_pos = file_obj.tell()
    
    # Seek to end to get size
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    
    # Restore position
    file_obj.seek(current_pos)
    
    return size

def validate_file_size(file_obj, max_size_mb=None):
    """
    Validate file size is within limits
    
    Args:
        file_obj: FileStorage object from Flask
        max_size_mb (int, optional): Max size in MB. Uses Config.MAX_CONTENT_LENGTH if None
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if max_size_mb is None:
        max_size_mb = Config.MAX_CONTENT_LENGTH / (1024 * 1024)
    
    size_bytes = get_file_size(file_obj)
    size_mb = size_bytes / (1024 * 1024)
    
    if size_mb > max_size_mb:
        return False, f"File size ({size_mb:.2f} MB) exceeds maximum allowed size ({max_size_mb} MB)"
    
    return True, None

def format_file_size(size_bytes):
    """
    Format file size in human-readable format
    
    Args:
        size_bytes (int): Size in bytes
    
    Returns:
        str: Formatted size (e.g., "1.5 MB", "500 KB")
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def ensure_upload_directory():
    """
    Ensure the upload directory exists
    
    Returns:
        str: Path to upload directory
    """
    upload_dir = os.path.join('static', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def get_upload_path(filename):
    """
    Get full path for uploaded file
    
    Args:
        filename (str): Name of the file
    
    Returns:
        str: Full path to save the file
    """
    upload_dir = ensure_upload_directory()
    return os.path.join(upload_dir, filename)

def save_encrypted_file(encrypted_data, filename):
    """
    Save encrypted file data to disk
    
    Args:
        encrypted_data (bytes): Encrypted file content
        filename (str): Filename to save as
    
    Returns:
        str: Path where file was saved
    """
    file_path = get_upload_path(filename)
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return file_path

def read_encrypted_file(filename):
    """
    Read encrypted file from disk
    
    Args:
        filename (str): Name of the file
    
    Returns:
        bytes: Encrypted file content
    """
    file_path = get_upload_path(filename)
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {filename}")
    
    with open(file_path, 'rb') as f:
        return f.read()

def delete_file(filename):
    """
    Delete file from disk
    
    Args:
        filename (str): Name of the file
    
    Returns:
        bool: True if deleted successfully
    """
    file_path = get_upload_path(filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    
    return False

def get_file_category(filename):
    """
    Determine the category of a file based on extension
    
    Args:
        filename (str): Name of the file
    
    Returns:
        str: Category name ('excel', 'image', 'document', 'text') or 'unknown'
    """
    ext = get_file_extension(filename)
    
    for category, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return category
    
    return 'unknown'