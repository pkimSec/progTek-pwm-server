# server/app.py
from flask import Flask
from flask_migrate import Migrate
from flask_session import Session
from flask_jwt_extended import JWTManager

from server.config import Config
from server.models import db, User, UserVaultMeta, Category

from server.routes import api
from server.vault_routes import vault_api
from server.user_routes import user_api
from server.category_routes import category_api

from server.limiter import limiter, init_limiter
from server.session import SessionManager
from server.security import SecurityHeaders
from server.db_utils import ensure_db_exists

import secrets, logging, base64, os
from datetime import datetime, timezone, UTC

def create_app(config_class=Config):
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Redis Session
    Session(app)
    
    # Configure logging
    app.start_time = datetime.now(UTC).isoformat()
    app.logger.setLevel(logging.INFO)

    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    SessionManager(app)
    SecurityHeaders(app)

    # Migrations
    migrate = Migrate(app, db)
    
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

    # Database creation moved to init_db.py

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)