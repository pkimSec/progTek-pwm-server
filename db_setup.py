# fixed_db_setup.py
from flask_migrate import Migrate
from alembic.command import init as alembic_init
from alembic.command import revision as alembic_revision
from alembic.command import upgrade as alembic_upgrade
import os

def setup_database():
    """Initialize database with migrations"""
    # Import here to avoid circular imports
    from server.app import create_app
    from server.models import db
    
    app = create_app()
    
    # Configure SQLite path if using SQLite
    if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
        # Ensure db directory exists
        os.makedirs('db', exist_ok=True)
    
    # Set up the migration environment
    migrate = Migrate(app, db)
    config = migrate.get_config()
    
    with app.app_context():
        try:
            # Initialize migrations directory
            alembic_init(config, 'migrations')
            print("Migrations initialized.")
            
            # Create migration
            alembic_revision(config, autogenerate=True, message="Initial database setup")
            print("Migration created.")
            
            # Apply migration
            alembic_upgrade(config, 'head')
            print("Migration applied.")
            
            print("Database setup complete!")
            return True
        except Exception as e:
            print(f"Error setting up database: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    setup_database()