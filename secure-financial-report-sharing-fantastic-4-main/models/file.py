from extensions import db
from datetime import datetime

class File(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    file_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    original_filename = db.Column(db.String(256), nullable=False)
    encrypted_filename = db.Column(db.String(256), nullable=False)
    parsed_filename = db.Column(db.String(256), nullable=True)
    file_type = db.Column(db.String(50), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    encrypted_size = db.Column(db.Integer, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encryption_algorithm = db.Column(db.String(10), nullable=False)
    cipher_mode = db.Column(db.String(10), nullable=True)
    
    # Salt for password-based encryption
    salt = db.Column(db.String(32), nullable=False)
    # --- AKHIR PERUBAHAN ---

    iv = db.Column(db.String(256), nullable=True)  # Hex encoded IV
    encryption_time = db.Column(db.Float, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Alias for compatibility
    
    # Relationships
    report = db.relationship('FinancialReport', backref='file', uselist=False, cascade='all, delete-orphan')
    
    # --- PERUBAHAN 2: HAPUS RELASI INI ---
    # Baris ini terhubung ke 'FileShare' yang lama, harus dihapus.
    # shares = db.relationship('FileShare', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    # --- AKHIR PERUBAHAN ---
    
    def __repr__(self):
        return f'<File {self.original_filename}>'