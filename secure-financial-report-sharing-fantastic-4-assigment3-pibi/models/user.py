from extensions import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    session_key = db.Column(db.String(256), nullable=True) 
    profile_picture_path = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_private = db.Column(db.Boolean, default=True, nullable=False)
    role = db.Column(db.String(20), default='organization', nullable=False)
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    authorized_users = db.relationship(
        'UserAccess',
        foreign_keys='UserAccess.owner_id',
        backref='owner',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    

    authorized_by = db.relationship(
        'UserAccess',
        foreign_keys='UserAccess.authorized_user_id',
        backref='authorized_user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    def __repr__(self):
        return f'<User {self.username}>'