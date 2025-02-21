# server/config.py
from datetime import timedelta

class Config:
    SECRET_KEY = 'dev-secret-key'  # Change in production
    SQLALCHEMY_DATABASE_URI = 'sqlite:///password_manager.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
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