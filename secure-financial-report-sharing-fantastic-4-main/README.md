# 🔐 Secure Financial Report Sharing System

<div align=center>

## Fantastic Four

|    NRP     |      Name                        |
| :--------: | :---------------------:          |
| 5025231029 | Clive Kenaz Fausto Sulastomo     |
| 5025231042| Rynofaldi Damario Dzaki          |
| 5025231201 | Fakhri Abrar W                   |
| 5025231240 | Danny Rachmadian Yusuf S.        |

</div>

<img width="640" height="854" alt="image" src="https://github.com/user-attachments/assets/564a4d06-b00e-49c5-a1ba-e9badced83c5" />

**A secure web-based file exchange system with symmetric encryption (AES, DES, RC4)**

---

## 📖 Table of Contents

1. [Project Overview](#-project-overview)
2. [Quick Start](#-quick-start)
3. [Project Structure](#-project-structure)
4. [Technology Stack](#-technology-stack)
5. [Key Features](#-key-features)
6. [Database Schema](#-database-schema)
7. [Development Guide](#-development-guide)
8. [Security Features](#-security-features)

---

## 🎯 Project Overview

A web-based Secure File Exchange System that allows users to upload, store, and share encrypted financial reports. The system uses **symmetric encryption** (AES, DES, RC4) to protect uploaded files and implements controlled data sharing with database-based access control.

### Key Features

✅ **User Management** - Secure registration/login with PBKDF2-SHA256  
✅ **File Encryption** - AES-256, DES, and RC4 with CBC mode  
✅ **File Upload/Download** - Encrypted storage with session key management  
✅ **File Sharing** - Share encrypted files with other users (coming soon)  
✅ **Excel Processing** - Extract and encrypt financial data from .xlsx files  
✅ **Performance Logging** - Track encryption/decryption times for comparison  
✅ **Access Control** - Database-based permissions and authentication  

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MySQL (via XAMPP recommended)
- Git

### 1. Clone Repository
```bash
git clone https://github.com/NETICS-Laboratory/secure-financial-report-sharing-fantastic-4.git
cd secure-financial-report-sharing-fantastic-4
```

### 2. Setup Environment
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows CMD)
venv\Scripts\activate.bat

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Database
```bash
# Copy environment template
copy .env.example .env

# Edit .env with your settings:
# SECRET_KEY=your-random-secret-key-here
# DATABASE_URL=mysql+pymysql://root:@localhost:3306/kamin_secure_financial_report
```

**Create MySQL database:**
- Open XAMPP Control Panel → Start MySQL
- Open phpMyAdmin: http://localhost/phpmyadmin
- Create database: `kamin_secure_financial_report`

### 4. Initialize Database
```bash
# Run migrations (creates all tables)
flask db upgrade
```

### 5. Run Application
```bash
python app.py
```

**Access at:** http://localhost:5000

### 6. Test It!
1. Click "Register" → Create an account
2. Login with your credentials
3. Upload a file with AES/DES/RC4 encryption
4. Download and verify the file decrypts correctly

---

##  Project Structure

```
secure-financial-report-sharing-fantastic-4/
├── app.py                      # Main Flask application
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (DON'T COMMIT!)
├── .env.example                # Environment template
├── extensions.py               # Flask extensions initialization
├── migrations/                 # Database migrations (Flask-Migrate)
│   └── versions/              # Migration files
├── models/                     # Database models (SQLAlchemy)
│   ├── __init__.py
│   ├── user.py                # User model
│   ├── file.py                # File metadata model
│   ├── report.py              # Financial report model
│   ├── share.py               # File sharing model
│   └── log.py                 # Crypto operations log model
├── encryption/                 # Encryption handlers
│   ├── __init__.py
│   ├── aes_handler.py         # AES-256-CBC encryption
│   ├── des_handler.py         # DES-CBC encryption
│   └── rc4_handler.py         # RC4 stream cipher
├── utils/                      # Utility functions
│   ├── __init__.py
│   ├── key_manager.py         # Session key & file key management
│   ├── file_handler.py        # File operations
│   ├── validators.py          # Input validation
│   └── logger.py              # Crypto operation logging
├── routes/                     # Flask blueprints (routes)
│   ├── __init__.py
│   ├── auth.py                # Authentication routes
│   ├── main.py                # Main routes (home, dashboard)
│   ├── files.py               # File upload/download/delete
|   └── sharing.py             # File sharing routes
├── templates/                  # HTML templates (Jinja2)
│   ├── base.html              # Base template with navbar
│   ├── index.html             # Landing page
│   ├── dashboard.html         # User dashboard
│   ├── upload.html            # File upload form
│   ├── files.html             # File listing page
│   ├── share.html             # Share file form 
│   ├── shared.html            # "Shared with me" list
│   └── auth/                  # Authentication templates
│       ├── login.html
│       └── register.html
├── static/                     # Static files
│   ├── css/
│   │   └── style.css
│   └── uploads/               # Encrypted file storage
│       └── .gitkeep
└── logs/                       # Application logs
    └── .gitkeep
```

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Flask 3.0.0 (Python) |
| **Database** | MySQL 8.x |
| **ORM** | SQLAlchemy 3.1.1 |
| **Migrations** | Flask-Migrate 4.0.5 |
| **Authentication** | Flask-Login 0.6.3 |
| **Password Hashing** | Werkzeug PBKDF2-SHA256 |
| **Encryption (AES)** | `cryptography` 41.0.7 |
| **Encryption (DES/RC4)** | `pycryptodome` 3.19.0 |
| **Excel Processing** | `openpyxl` 3.1.2 |
| **Database Driver** | PyMySQL 1.1.0 |
| **Frontend** | HTML5, CSS3, JavaScript |

---

## ✨ Key Features

### 1. User Authentication
- Secure registration with username/email uniqueness
- Login with "Remember Me" functionality
- Password hashing with PBKDF2-SHA256 (600,000 iterations)
- Session key generation for file key encryption
- Protected routes with `@login_required` decorator

### 2. File Encryption
- **AES-256-CBC**: Military-grade encryption (recommended)
- **DES-CBC**: Classic encryption standard
- **RC4**: Stream cipher for comparison
- Unique encryption key per file
- IV (Initialization Vector) for CBC modes
- File keys encrypted with user's session key

### 3. File Upload & Storage
- Validate file type (.xlsx, .png, .jpg, .pdf, .txt, etc.)
- Validate file size (max 16 MB)
- Generate UUID for unique filenames
- Encrypt file before storage
- Store encrypted filename, IV, algorithm in database
- Log encryption time for performance analysis

### 4. File Download & Decryption
- **Decrypt**: Download original file (automatic decryption)
- **Raw**: Download encrypted file (for verification)
- Access control (only file owner can download)
- Decrypt file key using session key
- Log decryption time

### 5. Excel Processing (.xlsx only)
- Parse Excel files with `openpyxl`
- Extract financial data from specific cells (B2, B3, B4)
- Encrypt each value individually
- Store in `financial_reports` table
- Note: Old .xls format not supported (ZIP format required)

### 6. Crypto Operation Logging
- Log every encryption/decryption operation
- Track algorithm used, file size, execution time
- Success/failure status
- Timestamp for audit trail

---

## 🗄️ Database Schema

### Tables

#### 1. `users`
```sql
id              INTEGER PRIMARY KEY
username        VARCHAR(80) UNIQUE NOT NULL
email           VARCHAR(120) UNIQUE NOT NULL
password_hash   VARCHAR(256) NOT NULL
session_key     VARCHAR(256)           -- Encrypted with master key
created_at      DATETIME NOT NULL
```

#### 2. `files`
```sql
id                  INTEGER PRIMARY KEY
file_uuid           VARCHAR(36) UNIQUE NOT NULL
original_filename   VARCHAR(256) NOT NULL
encrypted_filename  VARCHAR(256) NOT NULL
file_type           VARCHAR(50)
file_size           INTEGER
encrypted_size      INTEGER
owner_id            INTEGER FK → users.id
encryption_algorithm VARCHAR(10) NOT NULL    -- 'AES', 'DES', 'RC4'
cipher_mode         VARCHAR(10)              -- 'CBC', NULL
encrypted_key       VARCHAR(512) NOT NULL    -- File key encrypted with session key
iv                  VARCHAR(256)             -- Hex-encoded IV for CBC
encryption_time     FLOAT
uploaded_at         DATETIME NOT NULL
upload_date         DATETIME NOT NULL
```

#### 3. `financial_reports`
```sql
id              INTEGER PRIMARY KEY
file_id         INTEGER FK → files.id
revenue         TEXT                    -- Encrypted hex
revenue_iv      VARCHAR(256)
expenses        TEXT                    -- Encrypted hex
expenses_iv     VARCHAR(256)
net_profit      TEXT                    -- Encrypted hex
net_profit_iv   VARCHAR(256)
encrypted_key   VARCHAR(512)            -- Report key encrypted with session key
report_date     DATETIME NOT NULL
```

#### 4. `file_shares`
```sql
id                  INTEGER PRIMARY KEY
file_id             INTEGER FK → files.id
owner_id            INTEGER FK → users.id
shared_with_user_id INTEGER FK → users.id
permission          VARCHAR(20)         -- 'view', 'download'
shared_at           DATETIME NOT NULL
```

#### 5. `crypto_logs`
```sql
id              INTEGER PRIMARY KEY
operation       VARCHAR(20) NOT NULL    -- 'encrypt', 'decrypt'
algorithm       VARCHAR(10) NOT NULL    -- 'AES', 'DES', 'RC4'
file_id         INTEGER FK → files.id
user_id         INTEGER FK → users.id
execution_time  FLOAT NOT NULL
data_size       INTEGER NOT NULL
success         BOOLEAN NOT NULL
timestamp       DATETIME NOT NULL
```

---

## 💻 Development Guide

### Creating a New Model

**Example: Create a Comment model**

```python
# models/comment.py
from extensions import db
from datetime import datetime

class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Create migration:**
```bash
flask db migrate -m "Add comments table"
flask db upgrade
```

### Creating a New Route

**Example: Add a profile page**

```python
# routes/main.py
from flask import render_template
from flask_login import login_required, current_user

@main_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)
```

### Using Encryption Handlers

```python
from encryption.aes_handler import AESHandler
from utils.key_manager import generate_file_key

# Generate key
key = generate_file_key('AES')  # Returns 32 bytes for AES-256

# Initialize handler
handler = AESHandler(key)

# Encrypt
data = b"Secret message"
ciphertext, iv, encryption_time = handler.encrypt(data)

# Decrypt
plaintext, decryption_time = handler.decrypt(ciphertext, iv)
```

---

## Security Features

### Password Security
- **Algorithm**: PBKDF2-SHA256
- **Iterations**: 600,000 (OWASP recommended)
- **Salt**: Unique per password (auto-generated)
- **Format**: `pbkdf2:sha256:600000$salt$hash`

### File Encryption
- **AES**: 256-bit keys, CBC mode, random IV per file
- **DES**: 64-bit keys, CBC mode, random IV per file
- **RC4**: 128-bit keys, stream cipher (no IV)
- **Key Management**: File keys encrypted with user session keys

### Session Key Management
- Generated on first login (256-bit random)
- Stored base64-encoded in database
- Used to encrypt all file encryption keys
- Never transmitted to client

### Access Control
- Route protection with `@login_required`
- Owner verification before file access
- Foreign key constraints in database
- Prepared statements (SQLAlchemy ORM)

---
