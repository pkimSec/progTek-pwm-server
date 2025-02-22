# tests/test_security.py
import pytest
from flask import session
from datetime import datetime, timedelta, UTC

def test_security_headers(client):
    """Test that security headers are set correctly"""
    response = client.get('/api')  # Changed from '/' to '/api'
    
    # Check security headers
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'Content-Security-Policy' in response.headers
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'no-store' in response.headers.get('Cache-Control')
    assert response.headers.get('Pragma') == 'no-cache'

def test_session_creation(client, admin_headers):
    """Test session creation on login"""
    # Login with admin credentials
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    assert response.status_code == 200, f"Login failed: {response.get_json()}"
    
    # Check session cookie
    assert 'session=' in response.headers.get('Set-Cookie', '')
    
    # Make authenticated request
    response = client.get('/api/vault/entries', headers=admin_headers)
    assert response.status_code == 200
    
    # Check session data through session_transaction
    with client.session_transaction() as sess:
        assert sess.get('user_id') is not None
        assert sess.get('created_at') is not None

def test_session_expiry(client, admin_headers):
    """Test session expiration"""
    # First login
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    assert response.status_code == 200, f"Login failed: {response.get_json()}"
    
    # Artificially expire the session
    with client.session_transaction() as sess:
        sess['created_at'] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    
    # Try accessing protected endpoint
    response = client.get('/api/vault/entries', headers=admin_headers)
    assert response.status_code == 401, f"Expected 401, got {response.status_code}: {response.get_json()}"

def test_session_invalidation(client, admin_headers):
    """Test session invalidation on logout"""
    # First login
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    assert response.status_code == 200, f"Login failed: {response.get_json()}"
    
    # Verify session exists
    with client.session_transaction() as sess:
        assert sess.get('user_id') is not None
    
    # Logout
    response = client.post('/api/logout', headers=admin_headers)
    assert response.status_code == 200
    
    # Try accessing protected endpoint
    response = client.get('/api/vault/entries', headers=admin_headers)
    assert response.status_code == 401

def test_session_mismatch(client, admin_headers, user_headers):
    """Test session mismatch detection"""
    # Login as admin
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    assert response.status_code == 200, f"Admin login failed: {response.get_json()}"
    
    # Try to access with user headers but admin session
    response = client.get('/api/vault/entries', headers=user_headers)
    assert response.status_code == 401, f"Expected 401, got {response.status_code}: {response.get_json()}"
    assert 'Session mismatch' in response.get_json()['message']