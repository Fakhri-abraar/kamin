from extensions import db
from datetime import datetime

class FileAccessRequest(db.Model):
    __tablename__ = 'file_access_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # User requesting access
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File owner
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File being requested (optional - could be for specific file or all user files)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    
    # Status: 'pending', 'approved', 'denied'
    status = db.Column(db.String(20), default='pending', nullable=False)
    
    # Timestamps
    requested_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    responded_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    requester = db.relationship('User', foreign_keys=[requester_id], backref='sent_access_requests')
    owner = db.relationship('User', foreign_keys=[owner_id], backref='received_access_requests')
    file = db.relationship('File', foreign_keys=[file_id], backref='access_requests')
    
    # Prevent duplicate requests
    __table_args__ = (
        db.UniqueConstraint('requester_id', 'owner_id', 'file_id', name='unique_file_access_request'),
    )
    
    def __repr__(self):
        return f'<FileAccessRequest requester={self.requester_id} owner={self.owner_id} status={self.status}>'
