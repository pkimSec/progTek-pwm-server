def reset_database():
    """Reset database and create proper tables"""
    import os
    from sqlalchemy import inspect, text, MetaData
    from sqlalchemy.schema import CreateSchema
    
    # Import after function definition to avoid circular imports
    from server.app import create_app
    from server.models import db, User, Category
    import base64, secrets

    app = create_app()
    
    with app.app_context():
        try:
            # Get inspector to check database state
            inspector = inspect(db.engine)
            print("Current tables:", inspector.get_table_names())
            
            # Drop all tables if they exist
            print("Dropping all tables...")
            db.drop_all()
            
            # Reset SQLAlchemy metadata
            db.metadata.clear()
            
            # Explicitly define User model with quoted names for PostgreSQL
            class User(db.Model):
                __tablename__ = 'user_accounts'  # Different name to avoid keyword issues
                
                id = db.Column(db.Integer, primary_key=True)
                email = db.Column(db.String(120), unique=True)
                password_hash = db.Column(db.String(256))
                role = db.Column(db.String(20), nullable=False, default='user')
                invite_code = db.Column(db.String(36), unique=True)
                is_active = db.Column(db.Boolean, default=False)
                vault_key_salt = db.Column(db.String(64), nullable=True)
                
                def set_password(self, password):
                    from werkzeug.security import generate_password_hash
                    self.password_hash = generate_password_hash(password)
                
                def check_password(self, password):
                    from werkzeug.security import check_password_hash
                    return check_password_hash(self.password_hash, password)
                
                @staticmethod
                def generate_invite_code():
                    import uuid
                    return str(uuid.uuid4())
            
            # Create tables
            print("Creating tables...")
            db.create_all()
            
            # Verify tables were created
            inspector = inspect(db.engine)
            print("Tables after creation:", inspector.get_table_names())
            
            # Create admin user
            admin_password = 'changeme'
            admin_email = 'admin@localhost'
            vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Create admin user with vault key salt
            admin = User(
                email=admin_email,
                role='admin',
                is_active=True,
                vault_key_salt=vault_key_salt
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            
            # Commit to get user ID
            db.session.commit()
            
            # Get admin user ID for foreign keys
            admin_id = admin.id
            print(f"Created admin user with ID: {admin_id}")
            
            # Create default categories
            default_categories = ["Business", "Finance", "Personal", "Email", "Shopping"]
            for category_name in default_categories:
                category = Category(
                    user_id=admin_id,
                    name=category_name
                )
                db.session.add(category)
            
            # Commit all changes
            db.session.commit()
            
            print("==============================")
            print("Database reset complete")
            print(f"Admin email: {admin_email}")
            print(f"Admin password: {admin_password}")
            print("==============================")
            
            return True
        except Exception as e:
            print(f"Error setting up database: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    reset_database()