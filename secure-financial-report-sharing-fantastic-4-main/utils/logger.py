"""
Utility functions for logging crypto operations
Logs encryption/decryption activities to the database
"""
from datetime import datetime
from models.log import CryptoLog
from extensions import db

def log_crypto_operation(
    user_id,
    file_id,
    operation_type,
    algorithm,
    file_size,
    execution_time,
    success=True,
    error_message=None
):
    """
    Log a cryptographic operation to the database
    
    Args:
        user_id (int): ID of the user performing the operation
        file_id (int): ID of the file being encrypted/decrypted
        operation_type (str): 'encryption' or 'decryption'
        algorithm (str): 'AES', 'DES', or 'RC4'
        file_size (int): Size of the file in bytes
        execution_time (float): Time taken in seconds
        success (bool): Whether the operation succeeded
        error_message (str, optional): Error message if operation failed (not stored in DB currently)
    
    Returns:
        CryptoLog: The created log entry
    """
    # Map 'encryption'/'decryption' to 'encrypt'/'decrypt' for the model
    operation = 'encrypt' if operation_type == 'encryption' else 'decrypt'
    
    log_entry = CryptoLog(
        user_id=user_id,
        file_id=file_id,
        operation=operation,
        algorithm=algorithm,
        data_size=file_size,
        execution_time=execution_time,
        success=success,
        timestamp=datetime.utcnow()
    )
    
    db.session.add(log_entry)
    db.session.commit()
    
    return log_entry

def get_user_crypto_stats(user_id):
    """
    Get statistics about user's crypto operations
    
    Args:
        user_id (int): User ID
    
    Returns:
        dict: Statistics including total operations, average time, etc.
    """
    logs = CryptoLog.query.filter_by(user_id=user_id).all()
    
    if not logs:
        return {
            'total_operations': 0,
            'total_encryptions': 0,
            'total_decryptions': 0,
            'avg_encryption_time': 0,
            'avg_decryption_time': 0,
            'total_data_processed': 0
        }
    
    encryptions = [log for log in logs if log.operation == 'encrypt']
    decryptions = [log for log in logs if log.operation == 'decrypt']
    
    stats = {
        'total_operations': len(logs),
        'total_encryptions': len(encryptions),
        'total_decryptions': len(decryptions),
        'avg_encryption_time': sum(log.execution_time for log in encryptions) / len(encryptions) if encryptions else 0,
        'avg_decryption_time': sum(log.execution_time for log in decryptions) / len(decryptions) if decryptions else 0,
        'total_data_processed': sum(log.data_size for log in logs)
    }
    
    return stats

def get_algorithm_comparison(user_id=None):
    """
    Compare performance of different algorithms
    
    Args:
        user_id (int, optional): If provided, filter by user
    
    Returns:
        dict: Comparison data by algorithm
    """
    query = CryptoLog.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    logs = query.all()
    
    algorithms = {}
    for log in logs:
        algo = log.algorithm
        if algo not in algorithms:
            algorithms[algo] = {
                'total_operations': 0,
                'total_time': 0,
                'avg_time': 0,
                'total_size': 0
            }
        
        algorithms[algo]['total_operations'] += 1
        algorithms[algo]['total_time'] += log.execution_time
        algorithms[algo]['total_size'] += log.data_size
    
    # Calculate averages
    for algo in algorithms:
        if algorithms[algo]['total_operations'] > 0:
            algorithms[algo]['avg_time'] = algorithms[algo]['total_time'] / algorithms[algo]['total_operations']
    
    return algorithms
