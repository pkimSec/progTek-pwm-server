# server/app.py
from flask import Flask
from flask_jwt_extended import JWTManager
from server.config import Config
from server.models import db, User
from server.routes import api
from server.limiter import limiter, init_limiter
import secrets
import logging

def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Configure logging
    app.logger.setLevel(logging.INFO)

    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    init_limiter(app)

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

    # Create tables and admin user
    with app.app_context():
        db.create_all()
        
        admin = User.query.filter_by(role='admin', is_active=True).first()
        if not admin:
            admin_password = secrets.token_urlsafe(12)
            admin = User(
                email='admin@localhost',
                role='admin',
                is_active=True
            )
            admin.set_password(admin_password)
            db.session.add(admin)
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