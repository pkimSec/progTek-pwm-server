# tests/test_auth.py
def test_register_without_invite_code(client):
    response = client.post('/api/register', json={
        'email': 'user@test.com',
        'password': 'test_password'
    })
    assert response.status_code == 400
    assert 'Missing required fields' in response.get_json()['message']

def test_register_with_invalid_invite_code(client):
    response = client.post('/api/register', json={
        'email': 'user@test.com',
        'password': 'test_password',
        'invite_code': 'invalid_code'
    })
    assert response.status_code == 400
    assert 'Invalid invite code' in response.get_json()['message']

def test_register_and_login_success(client, admin_headers):
    # First create an invite code
    invite_response = client.post('/api/invite', headers=admin_headers)
    assert invite_response.status_code == 201, f"Failed to create invite: {invite_response.get_json()}"
    invite_code = invite_response.get_json()['invite_code']

    # Register new user
    register_response = client.post('/api/register', json={
        'email': 'user@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    assert register_response.status_code == 201

    # Try to login
    login_response = client.post('/api/login', json={
        'email': 'user@test.com',
        'password': 'test_password'
    })
    assert login_response.status_code == 200
    assert 'access_token' in login_response.get_json()
    assert login_response.get_json()['role'] == 'user'

def test_login_invalid_credentials(client):
    response = client.post('/api/login', json={
        'email': 'nonexistent@test.com',
        'password': 'wrong_password'
    })
    assert response.status_code == 401
    assert 'Invalid credentials' in response.get_json()['message']