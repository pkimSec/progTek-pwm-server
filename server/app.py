# server/app.py
from flask import Flask
from flask_jwt_extended import JWTManager
from server.config import Config
from server.models import db, User, UserVaultMeta
from server.routes import api
from server.vault_routes import vault_api
from server.user_routes import user_api
from server.limiter import limiter, init_limiter
from server.session import SessionManager
from server.security import SecurityHeaders
import secrets, logging, base64, os

def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Configure logging
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

    # Register blueprint
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(vault_api, url_prefix='/api')
    app.register_blueprint(user_api, url_prefix='/api')
    
    # Ensure database and tables exist
    with app.app_context():
        # Drop all tables first (since its in development)
        db.drop_all()
        # Create all tables fresh
        db.create_all()
        
        admin = User.query.filter_by(role='admin', is_active=True).first()
        if not admin:
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
                user_id=admin.id,
                key_salt=vault_key_salt
            )
            db.session.add(meta)
            
            # Commit both changes
            db.session.commit()
            
            print("==============================")
            print("Default admin account created:")
            print(f"Email: admin@localhost")
            print(f"Password: {admin_password}")
            print("==============================")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)