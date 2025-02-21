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