# server/limiter.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["20 per minute"],
    storage_uri="memory://"
)

def init_limiter(app):
    """Initialize rate limiter with app"""
    limiter.init_app(app)
    
    # Apply default rate limit to all routes
    @app.before_request
    def before_request():
        pass  # The limiter decorator handles the rate limiting