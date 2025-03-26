# server/app.py
import secrets
import logging
import base64
import os
from datetime import datetime, UTC

from flask import Flask
from flask_jwt_extended import JWTManager

from server.config import Config
from server.models import db, User, UserVaultMeta, Category

from server.routes import api
from server.vault_routes import vault_api
from server.user_routes import user_api
from server.category_routes import category_api

from server.session import SessionManager
from server.security import SecurityHeaders

def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Configure logging
    app.start_time = datetime.now(UTC).isoformat()
    app.logger.setLevel(logging.INFO)

    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    SessionManager(app)
    SecurityHeaders(app)
    
    # JWT configuration
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        try:
            user_id = int(identity)
            return db.session.get(User, user_id)
        except (ValueError, TypeError):
            return None

    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        try:
            user_id = int(identity)
            user = db.session.get(User, user_id)
            if user:
                return {"role": user.role}
        except (ValueError, TypeError):
            pass
        return {"role": None}

    # Register blueprints
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(vault_api, url_prefix='/api')
    app.register_blueprint(user_api, url_prefix='/api')
    app.register_blueprint(category_api, url_prefix='/api')
    
    # Ensure database and tables exist
    with app.app_context():
        # Create tables if they don't exist (don't drop existing tables)
        db.create_all()
        
        # Check if there's already an admin user
        admin = User.query.filter_by(role='admin', is_active=True).first()
        if not admin:
            # Only create admin if none exists
            app.logger.info("No admin user found. Creating default admin account.")
            
            # Generate admin credentials
            admin_password = secrets.token_urlsafe(12)
            vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Create admin user with vault salt
            admin = User(
                email='admin@localhost',
                role='admin',
                is_active=True,
                vault_key_salt=vault_key_salt
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            
            # Initialize admin's vault metadata
            meta = UserVaultMeta(
                user_id=1,  # Use 1 since it's the first user
                key_salt=vault_key_salt
            )
            db.session.add(meta)
            
            # Create default categories for admin
            default_categories = ["Business", "Finance", "Personal", "Email", "Shopping"]
            for category_name in default_categories:
                category = Category(
                    user_id=1,  # Use 1 since it's the first user
                    name=category_name
                )
                db.session.add(category)
            
            # Commit all changes
            db.session.commit()
            
            print("==============================")
            print("Default admin account created:")
            print(f"Email: admin@localhost")
            print(f"Password: {admin_password}")
            print("==============================")
        else:
            app.logger.info(f"Admin user found with email: {admin.email}")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)