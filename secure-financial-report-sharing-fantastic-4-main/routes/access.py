from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from extensions import db
from models import User, File
from models.access import UserAccess
from models.file_access_request import FileAccessRequest
from datetime import datetime
from utils.rsa_handler import (
    load_private_key, load_public_key, 
    decrypt_with_private_key, encrypt_with_public_key
)
from utils.nosql_handler import (
    get_file_key, get_user_private_key_enc, 
    get_user_public_key, store_shared_key
)

access_bp = Blueprint('access', __name__, url_prefix='/access')

@access_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Logika untuk mengubah status privat/publik
        is_private = request.form.get('is_private') == 'true'
        current_user.is_private = is_private
        db.session.commit()
        flash('Profile settings updated!', 'success')
        return redirect(url_for('access.settings'))

    # Ambil daftar pengguna yang telah Anda beri izin
    authorized_list = db.session.query(
        User.username
    ).join(
        UserAccess, User.id == UserAccess.authorized_user_id
    ).filter(
        UserAccess.owner_id == current_user.id
    ).all()
    
    # Render template baru yang akan kita buat nanti
    return render_template('access_settings.html', authorized_list=authorized_list)

@access_bp.route('/toggle-privacy', methods=['POST'])
@login_required
def toggle_privacy():
    """Toggle user privacy status between public and private"""
    current_user.is_private = not current_user.is_private
    db.session.commit()
    status = "Private" if current_user.is_private else "Public"
    flash(f'Your account is now {status}!', 'success')
    return redirect(url_for('main.dashboard'))

@access_bp.route('/grant', methods=['POST'])
@login_required
def grant_access():
    username = request.form.get('username')
    recipient = User.query.filter_by(username=username).first()

    if not recipient:
        flash(f'User "{username}" not found.', 'error')
        return redirect(url_for('access.settings'))
    
    if recipient.id == current_user.id:
        flash('You cannot grant access to yourself.', 'error')
        return redirect(url_for('access.settings'))

    # Cek apakah sudah ada
    existing_access = UserAccess.query.filter_by(
        owner_id=current_user.id,
        authorized_user_id=recipient.id
    ).first()
    
    if existing_access:
        flash(f'You have already granted access to {username}.', 'info')
        return redirect(url_for('access.settings'))

    # Buat izin baru
    new_access = UserAccess(
        owner_id=current_user.id,
        authorized_user_id=recipient.id
    )
    db.session.add(new_access)
    db.session.commit()
    flash(f'Access granted to {username}!', 'success')
    return redirect(url_for('access.settings'))

@access_bp.route('/request/<int:file_id>', methods=['POST'])
@login_required
def request_file_access(file_id):
    """Request access to a specific file"""
    if current_user.role != 'consultant':
        return jsonify({'success': False, 'message': 'Only Consultants can request access to files.'}), 403
    file = File.query.get_or_404(file_id)
    
    # Can't request access to your own file
    if file.owner_id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot request access to your own file'}), 400
    
    # Check if already requested
    existing_request = FileAccessRequest.query.filter_by(
        requester_id=current_user.id,
        owner_id=file.owner_id,
        file_id=file_id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'message': 'You have already requested access to this file'}), 400
    
    # Check if already approved
    approved_request = FileAccessRequest.query.filter_by(
        requester_id=current_user.id,
        owner_id=file.owner_id,
        file_id=file_id,
        status='approved'
    ).first()
    
    if approved_request:
        return jsonify({'success': False, 'message': 'You already have access to this file'}), 400
    
    # Check if there's a revoked or denied request - reuse it
    old_request = FileAccessRequest.query.filter_by(
        requester_id=current_user.id,
        owner_id=file.owner_id,
        file_id=file_id
    ).filter(FileAccessRequest.status.in_(['revoked', 'denied'])).first()
    
    if old_request:
        # Reuse the old request by updating its status
        old_request.status = 'pending'
        old_request.requested_at = datetime.utcnow()
        old_request.responded_at = None
    else:
        # Create new request
        new_request = FileAccessRequest(
            requester_id=current_user.id,
            owner_id=file.owner_id,
            file_id=file_id
        )
        db.session.add(new_request)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Access request sent successfully'})

access_bp.route('/request-user/<int:user_id>', methods=['POST'])
@login_required
def request_user_access(user_id):
    """Request access to all files of a user"""
    if current_user.role != 'consultant':
        return jsonify({'success': False, 'message': 'Only Consultants can request access.'}), 403
    owner = User.query.get_or_404(user_id)
    
    # Can't request access to yourself
    if owner.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot request access to your own files'}), 400
    
    # Check if already requested (file_id=None means all user files)
    existing_request = FileAccessRequest.query.filter_by(
        requester_id=current_user.id,
        owner_id=user_id,
        file_id=None,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'message': 'You have already requested access to this user\'s files'}), 400
    
    # Check if there's a revoked or denied request - reuse it
    old_request = FileAccessRequest.query.filter_by(
        requester_id=current_user.id,
        owner_id=user_id,
        file_id=None
    ).filter(FileAccessRequest.status.in_(['revoked', 'denied'])).first()
    
    if old_request:
        # Reuse the old request by updating its status
        old_request.status = 'pending'
        old_request.requested_at = datetime.utcnow()
        old_request.responded_at = None
    else:
        # Create new request
        new_request = FileAccessRequest(
            requester_id=current_user.id,
            owner_id=user_id,
            file_id=None  # None means all files
        )
        db.session.add(new_request)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Access request sent successfully'})

@access_bp.route('/respond-request/<int:request_id>/<string:action>', methods=['POST'])
@login_required
def respond_to_access_request(request_id, action):
    """Approve or deny an access request with Key Exchange"""
    access_request = FileAccessRequest.query.get_or_404(request_id)
    
    # Validasi pemilik
    if access_request.owner_id != current_user.id:
        flash('Permission denied.', 'error')
        return redirect(url_for('connections.notifications_page'))
    
    if action == 'approve':
        # [PENTING] Kita butuh password untuk membuka Private Key Organisasi
        # Password ini dikirim dari Modal Form di notifikasi
        password = request.form.get('password')
        
        if not password:
            flash('Password required to confirm identity and decrypt keys.', 'error')
            return redirect(url_for('connections.notifications_page'))

        try:
            # --- PROSES KEY EXCHANGE (Pertukaran Kunci) ---
            
            # 1. Ambil Encrypted Private Key milik Organisasi (Current User)
            owner_priv_enc = get_user_private_key_enc(current_user.id)
            if not owner_priv_enc:
                raise Exception("Owner private key not found.")
            
            # 2. Decrypt Private Key pakai Password Login
            # Ini langkah krusial: Membuka identitas digital Organisasi
            owner_private_key = load_private_key(owner_priv_enc, password)
            
            # 3. Ambil Encrypted File Key (Versi Owner) dari MongoDB
            if not access_request.file_id:
                # Jika request untuk semua file, logika harus diulang untuk semua file (looping).
                # Untuk penyederhanaan tugas ini, kita asumsikan per-file request.
                raise Exception("File specific request required for key sharing.")

            file_key_enc_owner = get_file_key(access_request.file_id, current_user.id)
            if not file_key_enc_owner:
                raise Exception("Original file key not found.")
                
            # 4. Decrypt File Key pakai Private Key Owner -> Dapat RAW AES KEY
            # Di sini kita mendapatkan kunci asli file yang telanjang (raw) sebentar
            raw_file_key = decrypt_with_private_key(owner_private_key, file_key_enc_owner)
            
            # 5. Ambil Public Key Consultant (Requester) dari MongoDB
            requester_pub_pem = get_user_public_key(access_request.requester_id)
            if not requester_pub_pem:
                raise Exception("Requester public key not found.")
            
            requester_public_key = load_public_key(requester_pub_pem)
            
            # 6. Encrypt RAW AES KEY pakai Public Key Consultant
            # Kita bungkus ulang kunci aslinya khusus untuk Consultant
            shared_key_enc = encrypt_with_public_key(requester_public_key, raw_file_key)
            
            # 7. Simpan Shared Key ke MongoDB untuk Consultant
            store_shared_key(access_request.file_id, access_request.requester_id, shared_key_enc)
            
            # ----------------------------------------------
            
            # Update status di database SQL
            access_request.status = 'approved'
            access_request.responded_at = datetime.utcnow()
            
            # Beri akses view (UserAccess model) agar muncul di list 'Shared with Me'
            existing_access = UserAccess.query.filter_by(
                owner_id=current_user.id,
                authorized_user_id=access_request.requester_id
            ).first()
            
            if not existing_access:
                new_access = UserAccess(
                    owner_id=current_user.id,
                    authorized_user_id=access_request.requester_id
                )
                db.session.add(new_access)
            
            db.session.commit()
            flash(f'Access granted! Key securely shared with {access_request.requester.username}.', 'success')
            
        except ValueError:
             # Error ini muncul dari cryptography jika password salah
            flash('Invalid password. Failed to decrypt your identity key.', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Key exchange failed: {str(e)}', 'error')

    elif action == 'deny':
        access_request.status = 'denied'
        access_request.responded_at = datetime.utcnow()
        db.session.commit()
        flash(f'Request denied.', 'info')
    
    return redirect(url_for('connections.notifications_page'))

@access_bp.route('/revoke/<int:access_id>', methods=['POST'])
@login_required
def revoke_access(access_id):
    """Revoke file access granted to a user"""
    # access_id is now a FileAccessRequest.id
    file_request = FileAccessRequest.query.get_or_404(access_id)
    
    # Only the owner can revoke
    if file_request.owner_id != current_user.id:
        flash('You do not have permission to revoke this access.', 'error')
        return redirect(url_for('connections.notifications_page'))
    
    requester = User.query.get(file_request.requester_id)
    file_name = file_request.file.original_filename if file_request.file else "all files"
    
    # Update the FileAccessRequest status to 'revoked'
    file_request.status = 'revoked'
    file_request.responded_at = datetime.utcnow()
    
    # Also remove the UserAccess record if it exists
    access = UserAccess.query.filter_by(
        owner_id=current_user.id,
        authorized_user_id=file_request.requester_id
    ).first()
    if access:
        db.session.delete(access)
    
    db.session.commit()
    flash(f'Access to {file_name} revoked from {requester.username}.', 'success')
    return redirect(url_for('connections.notifications_page'))