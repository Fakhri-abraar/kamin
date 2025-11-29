from extensions import db
from datetime import datetime

class CryptoLog(db.Model):
    __tablename__ = 'crypto_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    operation = db.Column(db.String(20), nullable=False)  # 'encrypt' or 'decrypt'
    algorithm = db.Column(db.String(10), nullable=False)  # 'AES', 'DES', 'RC4'
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    execution_time = db.Column(db.Float, nullable=False)  # in seconds
    data_size = db.Column(db.Integer, nullable=False)  # in bytes
    success = db.Column(db.Boolean, default=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<CryptoLog {self.operation} {self.algorithm}>'