# testing mysql connection: python test_mysql.py

import pymysql
from dotenv import load_dotenv
import os

load_dotenv()

# Parse DATABASE_URL
# Format: mysql+pymysql://username:password@host:port/database
db_url = os.environ.get('DATABASE_URL')
parts = db_url.replace('mysql+pymysql://', '').split('@')
user_pass = parts[0].split(':')
host_port_db = parts[1].split('/')

username = user_pass[0]
password = user_pass[1]
host_port = host_port_db[0].split(':')
host = host_port[0]
port = int(host_port[1]) if len(host_port) > 1 else 3306
database = host_port_db[1]

print("Testing MySQL connection...")
print(f"Host: {host}")
print(f"Port: {port}")
print(f"Database: {database}")
print(f"User: {username}")

try:
    # Connect to MySQL
    connection = pymysql.connect(
        host=host,
        port=port,
        user=username,
        password=password,
        database=database
    )
    
    print("✅ Connection successful!")
    
    # Test query
    with connection.cursor() as cursor:
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"MySQL version: {version[0]}")
    
    connection.close()
    print("✅ Test completed successfully!")
    
except Exception as e:
    print(f"❌ Connection failed: {e}")