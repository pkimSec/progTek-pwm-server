# Server-side patch for session.py

from flask import session, jsonify, request
from functools import wraps
from datetime import datetime, timedelta, UTC
from flask_jwt_extended import get_jwt, verify_jwt_in_request
import secrets, uuid

class SessionManager:
    def __init__(self, app=None):
        self.app = app
        self.active_sessions = {}  # In-memory storage for sessions (use Redis in production)
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
            # Check if we have a session cookie
            if session.get('created_at'):
                created = datetime.fromisoformat(session['created_at'])
                if datetime.now(UTC) - created.replace(tzinfo=UTC) > app.config['PERMANENT_SESSION_LIFETIME']:
                    session.clear()
                    
            # Alternative: Check for custom session ID header
            session_id = request.headers.get('X-Session-ID')
            if session_id and session_id in self.active_sessions:
                # If valid session ID header, use that session data
                sess_data = self.active_sessions[session_id]
                
                # Check if session is expired
                created = datetime.fromisoformat(sess_data['created_at'])
                if datetime.now(UTC) - created.replace(tzinfo=UTC) > app.config['PERMANENT_SESSION_LIFETIME']:
                    del self.active_sessions[session_id]
                else:
                    # Add session data to request context for the session validator
                    request.session_data = sess_data
                    request.session_id = session_id

def requires_active_session(f):
    """Decorator to check for active session or JWT"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()  # Verify JWT first
            # For API testing, just having a valid JWT is enough
            return f(*args, **kwargs)
        except:
            # Fall back to regular session check
            if not session.get('user_id'):
                return jsonify({'message': 'Active session required'}), 401
                
            return f(*args, **kwargs)
    return decorated_function

# Patch for the login route to support session ID
def add_session_id_to_login_response(user_id, role, response_data):
    """
    Add a session ID to a login response and store session data.
    Use this in your login route to enable the alternative session approach.
    """
    from flask import current_app
    
    # Get the session manager instance
    session_manager = current_app.extensions.get('session_manager')
    if not session_manager:
        return response_data  # No session manager found
    
    # Create a new session ID
    session_id = str(uuid.uuid4())
    
    # Store session data
    session_manager.active_sessions[session_id] = {
        'user_id': user_id,
        'role': role,
        'created_at': datetime.now(UTC).isoformat()
    }
    
    # Add session ID to response
    response_data['session_id'] = session_id
    
    return response_data