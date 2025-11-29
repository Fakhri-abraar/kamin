from flask import Flask
from config import Config
import pymysql
from routes.performance import performance_bp

# Important: Install PyMySQL as MySQLdb for SQLAlchemy
pymysql.install_as_MySQLdb()

# Import extensions
from extensions import db, login_manager, migrate

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'

# --- PERUBAHAN DI SINI ---
# IMPORTANT: Import all models here so Flask-Migrate can detect them!
# Must be AFTER db is initialized
from models import User, File, FinancialReport, CryptoLog
from models.access import UserAccess # Impor model baru
from models.connection import Connection # Impor model Connection
# Hapus: from models import FileShare
# --- AKHIR PERUBAHAN ---

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Import and register blueprints
from routes.auth import auth_bp
from routes.main import main_bp
from routes.files import files_bp

# Import route blueprints
from routes.access import access_bp
from routes.connections import connections_bp

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(files_bp)
app.register_blueprint(performance_bp)
app.register_blueprint(access_bp)
app.register_blueprint(connections_bp)

if __name__ == '__main__':
    print("🚀 Starting Flask development server...")
    print("📂 Database:", app.config['SQLALCHEMY_DATABASE_URI'])
    print("💡 Access at: http://localhost:5000")
    app.run(debug=True, port=5000)