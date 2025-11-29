"""
Authentication routes: register, login, logout
"""
import os
import base64
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from models import User
from utils.rsa_handler import generate_key_pair, serialize_private_key, serialize_public_key
from utils.nosql_handler import store_user_keys

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'organization')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('auth/register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters!', 'error')
            return render_template('auth/register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            private_key, public_key = generate_key_pair()
            encrypted_private_key_pem = serialize_private_key(private_key, password)
            public_key_pem = serialize_public_key(public_key)
            store_user_keys(new_user.id, public_key_pem, encrypted_private_key_pem)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            return render_template('auth/register.html')
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        # Validation
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('auth/login.html')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password!', 'error')
            return render_template('auth/login.html')
        
        # Generate session key if user doesn't have one
        if not user.session_key:
            # Generate 256-bit (32 bytes) session key
            session_key = os.urandom(32)
            # Store as base64 string
            user.session_key = base64.b64encode(session_key).decode('utf-8')
            db.session.commit()
        
        # Login user
        login_user(user, remember=remember)
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
