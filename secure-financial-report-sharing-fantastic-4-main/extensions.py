"""
Flask extensions initialization.
Separate file to avoid circular imports between app.py and models.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

# Initialize extensions (but don't attach to app yet)
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
