from extensions import db
from app import app

def fix_migrations():
    with app.app_context():
        # Check if the migration is already in alembic_version
        result = db.session.execute("SELECT version_num FROM alembic_version").fetchall()
        current_version = result[0][0] if result else None
        print(f"Current version: {current_version}")
        
        if current_version != '6ea41a528990':
            # Insert the problematic migration as completed
            db.session.execute("INSERT INTO alembic_version (version_num) VALUES ('6ea41a528990')")
            db.session.commit()
            print("Successfully marked migration 6ea41a528990 as completed")
        else:
            print("Migration is already marked as completed")

if __name__ == '__main__':
    fix_migrations()