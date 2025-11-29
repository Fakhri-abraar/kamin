from flask import Blueprint, render_template
from flask_login import login_required
from extensions import db
from models import CryptoLog, File

performance_bp = Blueprint('performance', __name__, url_prefix='/performance')

@performance_bp.route('/', defaults={'file_type': 'all'})
@performance_bp.route('/<string:file_type>')
@login_required
def show_performance(file_type):
    """Menampilkan dasbor perbandingan performa, bisa difilter berdasarkan tipe file."""
    
    # Query dasar untuk logs
    log_query = db.session.query(CryptoLog).join(File, CryptoLog.file_id == File.id)
    file_query = File.query

    # Terapkan filter jika bukan 'all'
    if file_type != 'all':
        log_query = log_query.filter(File.file_type == file_type)
        file_query = file_query.filter(File.file_type == file_type)

    logs = log_query.all()
    files = file_query.all()
    
    # Inisialisasi struktur data untuk statistik
    stats = {
        'AES': {'encrypt_count': 0, 'encrypt_time': 0, 'decrypt_count': 0, 'decrypt_time': 0},
        'DES': {'encrypt_count': 0, 'encrypt_time': 0, 'decrypt_count': 0, 'decrypt_time': 0},
        'RC4': {'encrypt_count': 0, 'encrypt_time': 0, 'decrypt_count': 0, 'decrypt_time': 0},
    }
    
    # Proses setiap log
    for log in logs:
        algo = log.algorithm
        if algo in stats:
            if log.operation == 'encrypt':
                stats[algo]['encrypt_count'] += 1
                stats[algo]['encrypt_time'] += log.execution_time
            elif log.operation == 'decrypt':
                stats[algo]['decrypt_count'] += 1
                stats[algo]['decrypt_time'] += log.execution_time
    
    # Hitung rata-rata waktu
    for algo in stats:
        if stats[algo]['encrypt_count'] > 0:
            stats[algo]['avg_encrypt_time'] = stats[algo]['encrypt_time'] / stats[algo]['encrypt_count']
        else:
            stats[algo]['avg_encrypt_time'] = 0
            
        if stats[algo]['decrypt_count'] > 0:
            stats[algo]['avg_decrypt_time'] = stats[algo]['decrypt_time'] / stats[algo]['decrypt_count']
        else:
            stats[algo]['avg_decrypt_time'] = 0

    # Hitung statistik ukuran
    size_stats = {
        'AES': {'count': 0, 'total_original': 0, 'total_encrypted': 0},
        'DES': {'count': 0, 'total_original': 0, 'total_encrypted': 0},
        'RC4': {'count': 0, 'total_original': 0, 'total_encrypted': 0},
    }

    for f in files:
        algo = f.encryption_algorithm
        if algo in size_stats:
            size_stats[algo]['count'] += 1
            size_stats[algo]['total_original'] += f.file_size
            size_stats[algo]['total_encrypted'] += f.encrypted_size
    
    for algo in size_stats:
        if size_stats[algo]['count'] > 0:
            avg_original = size_stats[algo]['total_original'] / size_stats[algo]['count']
            avg_encrypted = size_stats[algo]['total_encrypted'] / size_stats[algo]['count']
            overhead = ((avg_encrypted - avg_original) / avg_original) * 100 if avg_original > 0 else 0
            size_stats[algo]['avg_overhead_percent'] = overhead
        else:
            size_stats[algo]['avg_overhead_percent'] = 0
            
    # Siapkan data untuk Chart.js
    chart_labels = list(stats.keys())
    encryption_times = [data['avg_encrypt_time'] for data in stats.values()]
    decryption_times = [data['avg_decrypt_time'] for data in stats.values()]

    # Tipe file yang tersedia untuk filter
    available_types = ['excel', 'image', 'text']

    return render_template(
        'performance.html',
        stats=stats,
        size_stats=size_stats,
        chart_labels=chart_labels,
        encryption_times=encryption_times,
        decryption_times=decryption_times,
        current_filter=file_type,
        available_types=available_types
    )