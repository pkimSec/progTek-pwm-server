# server/security.py
import pytest
from functools import wraps
from flask import make_response, request, jsonify, current_app

class SecurityHeaders:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        
        @app.after_request
        def add_security_headers(response):
            if not app.testing:  # Only enforce HTTPS in non-testing environment
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Adjust CSP for testing
            if app.testing:
                csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'"
            else:
                csp = "default-src 'self'; script-src 'self'; connect-src 'self'"
            
            response.headers['Content-Security-Policy'] = csp
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            
            return response

def requires_secure_transport(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # For production behind Nginx
        if current_app.config.get('TESTING', False):
            return f(*args, **kwargs)
            
        # Skip check for localhost or development
        if request.remote_addr == '127.0.0.1' or request.host.startswith('localhost'):
            return f(*args, **kwargs)
            
        # Check X-Forwarded-Proto header (from Nginx)
        forwarded_proto = request.headers.get('X-Forwarded-Proto')
        if forwarded_proto == 'https':
            return f(*args, **kwargs)
            
        # Direct HTTPS check
        if not current_app.testing and not request.is_secure:
            return make_response(jsonify({
                'message': 'HTTPS required'
            }), 403)
        return f(*args, **kwargs)
    return decorated_function