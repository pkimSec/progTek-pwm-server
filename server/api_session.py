# server/api_session.py
from flask import request, jsonify
from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from datetime import datetime, timedelta
import uuid

# Dictionary to store API sessions (replace with Redis in production)
api_sessions = {}

def create_api_session(user_id):
    """Create a session token for API clients"""
    session_token = str(uuid.uuid4())
    api_sessions[session_token] = {
        'user_id': user_id,
        'created_at': datetime.now()
    }
    return session_token


def get_api_session():
    """Get API session from header"""
    # Check both header variations for backward compatibility
    session_token = request.headers.get('X-API-Session-Token') or request.headers.get('X-Session-ID')
    if session_token and session_token in api_sessions:
        return api_sessions[session_token]
    return None

def requires_api_session(f):
    """Decorator for endpoints that require an API session"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check JWT first
        verify_jwt_in_request()
        jwt_identity = get_jwt_identity()
        
        # Then check API session
        api_session = get_api_session()
        if not api_session:
            return jsonify({"message": "API session required"}), 401
            
        # Check session matches JWT identity
        if str(api_session['user_id']) != str(jwt_identity):
            return jsonify({"message": "Session mismatch"}), 401
            
        return f(*args, **kwargs)
    return decorated