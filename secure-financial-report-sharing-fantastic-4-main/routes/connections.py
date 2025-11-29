"""
Connection management routes
Handles connection requests, listing, accepting/rejecting
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime
from flask_login import login_required, current_user
from extensions import db
from models.user import User
from models.connection import Connection

connections_bp = Blueprint('connections', __name__, url_prefix='/connections')

@connections_bp.route('/notifications-page')
@login_required
def notifications_page():
    """Show notifications page"""
    from models.access import UserAccess
    from models.file import File
    from models.file_access_request import FileAccessRequest
    
    # Get pending connection requests
    pending_requests = Connection.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).order_by(Connection.created_at.desc()).all()
    
    # Get accepted connections
    accepted_connections = Connection.query.filter(
        ((Connection.requester_id == current_user.id) | 
         (Connection.receiver_id == current_user.id)) &
        (Connection.status == 'accepted')
    ).order_by(Connection.updated_at.desc()).all()
    
    # Get granted file access (approved file access requests where I'm the owner)
    granted_access = FileAccessRequest.query.filter_by(
        owner_id=current_user.id,
        status='approved'
    ).filter(FileAccessRequest.file_id.isnot(None)).order_by(FileAccessRequest.responded_at.desc()).all()
    
    # Get pending file access requests (where I'm the owner)
    pending_file_requests = FileAccessRequest.query.filter_by(
        owner_id=current_user.id,
        status='pending'
    ).order_by(FileAccessRequest.requested_at.desc()).all()
    
    return render_template(
        'notifications.html',
        pending_requests=pending_requests,
        accepted_connections=accepted_connections,
        granted_access=granted_access,
        pending_file_requests=pending_file_requests
    )

@connections_bp.route('/list')
@login_required
def list_connections():
    """Show list of accepted connections and pending requests"""
    # Get accepted connections
    accepted_connections = Connection.query.filter(
        ((Connection.requester_id == current_user.id) | 
         (Connection.receiver_id == current_user.id)) &
        (Connection.status == 'accepted')
    ).all()
    
    # Get pending requests received
    pending_requests = Connection.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).all()
    
    connected_users = []
    for conn in accepted_connections:
        other_user = conn.receiver if conn.requester_id == current_user.id else conn.requester
        connected_users.append({
            'user': other_user,
            'connected_since': conn.updated_at
        })
    
    pending_users = [{'user': conn.requester, 'requested_at': conn.created_at} 
                    for conn in pending_requests]
    
    return render_template(
        'connections.html',
        connected_users=connected_users,
        pending_requests=pending_users
    )

@connections_bp.route('/request/<int:user_id>', methods=['POST'])
@login_required
def request_connection(user_id):
    """Send a connection request to another user"""
    if user_id == current_user.id:
        flash('You cannot connect with yourself', 'error')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Check if connection already exists
    existing = Connection.query.filter(
        ((Connection.requester_id == current_user.id) & (Connection.receiver_id == user_id)) |
        ((Connection.requester_id == user_id) & (Connection.receiver_id == current_user.id))
    ).first()
    
    if existing:
        if existing.status == 'pending':
            flash('Connection request already sent', 'info')
        elif existing.status == 'accepted':
            flash('Already connected with this user', 'info')
        else:
            flash('Cannot send request at this time', 'error')
        return redirect(url_for('files.view_user_files', username=user.username))
    
    # Create new connection request
    connection = Connection(
        requester_id=current_user.id,
        receiver_id=user_id,
        status='pending'
    )
    db.session.add(connection)
    db.session.commit()
    
    flash(f'Connection request sent to {user.username}', 'success')
    return redirect(url_for('files.view_user_files', username=user.username))

@connections_bp.route('/respond/<int:connection_id>/<string:action>', methods=['POST'])
@login_required
def respond_to_request(connection_id, action):
    """Accept or reject a connection request"""
    if action not in ['accept', 'reject']:
        flash('Invalid action', 'error')
        return redirect(url_for('connections.notifications_page'))

    connection = Connection.query.get_or_404(connection_id)
    
    if connection.receiver_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('connections.notifications_page'))
    
    if connection.status != 'pending':
        flash('This request has already been processed', 'info')
        return redirect(url_for('connections.notifications_page'))
    
    try:
        if action == 'accept':
            connection.status = 'accepted'
            connection.updated_at = datetime.utcnow()
            requester = User.query.get(connection.requester_id)
            flash(f'Connection request accepted! You are now connected with {requester.username}', 'success')
        else:  # reject
            connection.status = 'rejected'
            flash('Connection request rejected', 'success')
        
        db.session.commit()
        return redirect(url_for('connections.notifications_page'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing request: {str(e)}', 'error')
        return redirect(url_for('connections.notifications_page'))

@connections_bp.route('/remove/<int:user_id>', methods=['POST'])
@login_required
def remove_connection(user_id):
    """Remove an existing connection"""
    connection = Connection.query.filter(
        ((Connection.requester_id == current_user.id) & (Connection.receiver_id == user_id)) |
        ((Connection.requester_id == user_id) & (Connection.receiver_id == current_user.id)),
        Connection.status == 'accepted'
    ).first_or_404()
    
    other_user = User.query.get(user_id)
    
    db.session.delete(connection)
    db.session.commit()
    
    flash(f'Connection with {other_user.username} removed', 'success')
    return redirect(url_for('connections.list_connections'))

@connections_bp.route('/check-status/<int:user_id>')
@login_required
def check_connection_status(user_id):
    """Check connection status with a user (for AJAX calls)"""
    if user_id == current_user.id:
        return jsonify({'status': 'self'})
    
    connection = Connection.query.filter(
        ((Connection.requester_id == current_user.id) & (Connection.receiver_id == user_id)) |
        ((Connection.requester_id == user_id) & (Connection.receiver_id == current_user.id))
    ).first()
    
    if not connection:
        return jsonify({'status': 'none'})
        
    return jsonify({
        'status': connection.status,
        'is_requester': connection.requester_id == current_user.id
    })

@connections_bp.route('/notifications')
@login_required
def get_notifications():
    """Get user's connection notifications and file access requests"""
    from models.file_access_request import FileAccessRequest
    
    # Get pending connection requests
    pending_requests = Connection.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).order_by(Connection.created_at.desc()).all()
    
    # Get pending file access requests
    pending_file_requests = FileAccessRequest.query.filter_by(
        owner_id=current_user.id,
        status='pending'
    ).order_by(FileAccessRequest.requested_at.desc()).all()
    
    notifications = []
    
    # Add connection requests
    for request in pending_requests:
        requester = User.query.get(request.requester_id)
        time_diff = datetime.utcnow() - request.created_at
        
        if time_diff.days > 0:
            time_ago = f"{time_diff.days} days ago"
        elif time_diff.seconds > 3600:
            hours = time_diff.seconds // 3600
            time_ago = f"{hours} hours ago"
        elif time_diff.seconds > 60:
            minutes = time_diff.seconds // 60
            time_ago = f"{minutes} minutes ago"
        else:
            time_ago = "just now"
        
        notifications.append({
            'type': 'connection_request',
            'connection_id': str(request.id),  # Convert to string for JS
            'sender': requester.username,
            'message': f"{requester.username} wants to connect with you",
            'time_ago': time_ago,
            'is_read': False,
            'requester_id': requester.id
        })
    
    # Add file access requests
    for file_request in pending_file_requests:
        requester = file_request.requester
        time_diff = datetime.utcnow() - file_request.requested_at
        
        if time_diff.days > 0:
            time_ago = f"{time_diff.days} days ago"
        elif time_diff.seconds > 3600:
            hours = time_diff.seconds // 3600
            time_ago = f"{hours} hours ago"
        elif time_diff.seconds > 60:
            minutes = time_diff.seconds // 60
            time_ago = f"{minutes} minutes ago"
        else:
            time_ago = "just now"
        
        if file_request.file:
            message = f"{requester.username} requests access to {file_request.file.original_filename}"
        else:
            message = f"{requester.username} requests access to your files"
        
        notifications.append({
            'type': 'file_access_request',
            'request_id': str(file_request.id),
            'sender': requester.username,
            'message': message,
            'time_ago': time_ago,
            'is_read': False,
            'requester_id': requester.id
        })
    
    return jsonify({'notifications': notifications})