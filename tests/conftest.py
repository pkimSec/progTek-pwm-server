# tests/conftest.py
import pytest
from server.app import create_app
from server.models import db, User
from server.config import Config
from server.vault_routes import vault_api
from datetime import timedelta
from flask_jwt_extended import create_access_token
import logging

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_SECRET_KEY = 'test-jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECRET_KEY = 'test-secret-key'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_TYPE = 'Bearer'
    pass

@pytest.fixture(scope='function')
def app():
    """Create application for the tests."""
    app = create_app(TestConfig)
    app.logger.setLevel(logging.DEBUG)
    app.register_blueprint(vault_api, url_prefix='/api')
    return app

@pytest.fixture(scope='function')
def app_context(app):
    """Create app context for the tests."""
    with app.app_context() as ctx:
        from server.models import User, PasswordEntry, UserVaultMeta, PasswordEntryVersion
        db.create_all()
        
        # Create test admin user
        admin = User(
            email='test_admin@localhost',
            role='admin',
            is_active=True
        )
        admin.set_password('admin_password')
        db.session.add(admin)
        db.session.commit()
        
        yield ctx
        
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='function')
def client(app, app_context):
    """Create test client."""
    return app.test_client()

@pytest.fixture(scope='function')
def admin_headers(app, client):
    """Get admin token through actual login."""
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    
    assert response.status_code == 200, f"Login failed with response: {response.get_json()}"
    data = response.get_json()
    token = data['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture(scope='function')
def user_headers(client, admin_headers):
    """Create a regular user and get auth headers"""
    # Create invite code using admin token
    invite_response = client.post('/api/invite', headers=admin_headers)
    assert invite_response.status_code == 201, f"Failed to create invite: {invite_response.get_json()}"
    invite_code = invite_response.get_json()['invite_code']
    
    # Register new user
    register_response = client.post('/api/register', json={
        'email': 'test_user@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    assert register_response.status_code == 201, f"Failed to register user: {register_response.get_json()}"
    
    # Login as new user
    login_response = client.post('/api/login', json={
        'email': 'test_user@test.com',
        'password': 'test_password'
    })
    assert login_response.status_code == 200, f"Failed to login as user: {login_response.get_json()}"
    
    token = login_response.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}