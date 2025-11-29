from extensions import db
from datetime import datetime

class UserAccess(db.Model):
    __tablename__ = 'user_access'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Pengguna yang memberi izin (User A)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Pengguna yang diberi izin (User B)
    authorized_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    granted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Unique constraint: User A tidak bisa memberi izin User B dua kali
    __table_args__ = (
        db.UniqueConstraint('owner_id', 'authorized_user_id', name='unique_user_access'),
    )
    
    def __repr__(self):
        return f'<UserAccess owner={self.owner_id} grants to={self.authorized_user_id}>'