# server/api_session.py
from flask import request, jsonify, current_app
from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from datetime import datetime, timedelta
import uuid
import redis
import json

# Dictionary to store API sessions (replace with Redis in production)
api_sessions = {}

def get_redis():
    """Get Redis connection for API sessions"""
    if not hasattr(get_redis, 'conn'):
        redis_url = current_app.config.get('SESSION_REDIS')
        get_redis.conn = redis_url
    return get_redis.conn

def create_api_session(user_id):
    """Create a session token for API clients"""
    session_token = str(uuid.uuid4())
    session_data = {
        'user_id': user_id,
        'created_at': datetime.now().isoformat(),
        'last_activity': datetime.now().isoformat()
    }
    get_redis().setex(f"api_session:{session_token}", 
                     int(current_app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()),
                     json.dumps(session_data))
    return session_token

def get_api_session():
    """Get API session from header"""
    session_token = request.headers.get('X-API-Session-Token') or request.headers.get('X-Session-ID')
    if session_token:
        session_data = get_redis().get(f"api_session:{session_token}")
        if session_data:
            return json.loads(session_data)
    return None

def update_session_activity(session_token):
    """Update last activity timestamp for a session"""
    if session_token:
        redis_key = f"api_session:{session_token}"
        session_data = get_redis().get(redis_key)
        if session_data:
            session_data = json.loads(session_data)
            session_data['last_activity'] = datetime.now().isoformat()
            get_redis().setex(redis_key,
                             int(current_app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()),
                             json.dumps(session_data))
            return True
    return False

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
            
        # Update session activity
        session_token = request.headers.get('X-API-Session-Token') or request.headers.get('X-Session-ID')
        update_session_activity(session_token)
            
        return f(*args, **kwargs)
    return decorated