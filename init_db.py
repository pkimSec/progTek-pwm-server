from sqlalchemy import inspect, text, MetaData
import os

def init_database():
    """Initialize the database with proper table names for PostgreSQL"""
    # Import here to avoid circular imports
    from server.app import create_app
    from server.models import db, User, UserVaultMeta, Category, PasswordEntry, PasswordEntryVersion
    import base64
    
    # Create app with single worker for initialization
    os.environ['GUNICORN_WORKERS'] = '1'  # Force single worker for init
    app = create_app()
    
    with app.app_context():
        try:
            # Get current tables
            inspector = inspect(db.engine)
            print(f"Current tables: {inspector.get_table_names()}")
            
            # Drop existing tables to start fresh
            db.drop_all()
            print("All tables dropped")
            
            # Update model tablenames
            User.__tablename__ = 'users'
            Category.__tablename__ = 'categories'
            PasswordEntry.__tablename__ = 'password_entries'
            PasswordEntryVersion.__tablename__ = 'password_entry_versions'
            UserVaultMeta.__tablename__ = 'user_vault_metas'
            
            # Create tables with new names
            db.create_all()
            print("Tables created with PostgreSQL-friendly names")
            
            # Check the tables
            inspector = inspect(db.engine)
            print(f"Tables after creation: {inspector.get_table_names()}")
            
            # Create admin user
            admin_password = 'changeme'
            vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            admin = User(
                email='admin@pwm',
                role='admin',
                is_active=True,
                vault_key_salt=vault_key_salt
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.flush()  # Get ID without committing
            
            # Create user vault metadata
            meta = UserVaultMeta(
                user_id=admin.id,
                key_salt=vault_key_salt
            )
            db.session.add(meta)
            
            # Create default categories
            default_categories = ["Business", "Finance", "Personal", "Email", "Shopping"]
            for category_name in default_categories:
                category = Category(
                    user_id=admin.id,
                    name=category_name
                )
                db.session.add(category)
            
            # Commit all changes
            db.session.commit()
            
            print("==============================")
            print("Database initialized successfully")
            print("Admin credentials:")
            print(f"Email: admin@localhost")
            print(f"Password: {admin_password}")
            print("==============================")
            
            return True
        except Exception as e:
            print(f"Error initializing database: {str(e)}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == "__main__":
    init_database()