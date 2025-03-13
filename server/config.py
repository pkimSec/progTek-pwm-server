# server/config.py
import os
from datetime import timedelta
import redis

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
        
    # Database configuration
    DB_USER = os.environ.get('DB_USER', 'postgres')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'password')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'password_manager')
    
    # Construct database URI
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

    # Redis Session Setup
    SESSION_TYPE = 'redis'
    SESSION_REDIS = redis.from_url('redis://redis:6379/0')
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'pwm:'
    
    # JWT Configuration
    JWT_SECRET_KEY = 'jwt-secret-key'  # Change in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ERROR_MESSAGE_KEY = 'msg'
    
    # Additional app settings
    DEBUG = False
    TESTING = False

    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Security Settings
    PREFERRED_URL_SCHEME = 'https'