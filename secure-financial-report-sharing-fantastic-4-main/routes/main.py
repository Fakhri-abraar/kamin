"""
Main routes: dashboard, home
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import User # <-- Pastikan User diimpor

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - requires login"""
    return render_template('dashboard.html', user=current_user)

@main_bp.route('/search', methods=['GET', 'POST'])
@login_required
def search_user():
    """Handle user search - shows search page and handles search"""
    users = []
    search_query = ''
    
    if request.method == 'POST':
        search_query = request.form.get('username', '')
        if search_query:
            # Use case-insensitive search and exclude current user
            users = User.query.filter(
                User.username.ilike(f"%{search_query}%"),
                User.id != current_user.id
            ).all()
    
    return render_template('search_results.html', users=users, search_query=search_query)

@main_bp.route('/template')
@login_required
def template_page():
    """Excel template download page"""
    return render_template('template.html')