# server/session.py
from flask import session, jsonify
from functools import wraps
from datetime import datetime, timedelta, UTC
from flask_jwt_extended import get_jwt, verify_jwt_in_request
import secrets

class SessionManager:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        # Configure session settings
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', timedelta(hours=1))
        app.config.setdefault('SESSION_COOKIE_SECURE', True)
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Strict')
        
        if not app.config.get('SECRET_KEY'):
            app.config['SECRET_KEY'] = secrets.token_hex(32)

        @app.before_request
        def validate_session():
            if session.get('created_at'):
                created = datetime.fromisoformat(session['created_at'])
                if datetime.now(UTC) - created.replace(tzinfo=UTC) > app.config['PERMANENT_SESSION_LIFETIME']:
                    session.clear()

def requires_active_session(f):
    """Decorator to check for active session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()  # Verify JWT first
        
        # Check if session exists and is valid
        if not session.get('user_id'):
            return jsonify({'message': 'Active session required'}), 401
            
        # Check if session matches JWT
        jwt_data = get_jwt()
        if str(session['user_id']) != str(jwt_data['sub']):
            return jsonify({'message': 'Session mismatch'}), 401
            
        return f(*args, **kwargs)
    return decorated_function