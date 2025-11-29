from extensions import db
from datetime import datetime

class Connection(db.Model):
    __tablename__ = 'connections'
    
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    requester = db.relationship('User', foreign_keys=[requester_id], backref=db.backref('sent_connections', lazy='dynamic'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_connections', lazy='dynamic'))

    def __repr__(self):
        return f'<Connection {self.requester_id} -> {self.receiver_id} ({self.status})>'