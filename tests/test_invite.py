# tests/test_invite.py
def test_create_invite_as_admin(client, admin_headers):
    # First verify the token works
    debug_response = client.get('/api/debug/token', headers=admin_headers)
    assert debug_response.status_code == 200, f"Token verification failed: {debug_response.get_json()}"
    debug_data = debug_response.get_json()
    assert debug_data['role'] == 'admin'

    response = client.post('/api/invite', headers=admin_headers)
    assert response.status_code == 201
    data = response.get_json()
    assert 'invite_code' in data
    assert isinstance(data['invite_code'], str)

def test_create_invite_without_token(client):
    response = client.post('/api/invite')
    assert response.status_code == 401
    data = response.get_json()
    assert 'msg' in data

def test_create_invite_as_user(client, admin_headers):
    # First create an invite as admin
    invite_response = client.post('/api/invite', headers=admin_headers)
    assert invite_response.status_code == 201, f"Failed to create invite: {invite_response.get_json()}"
    invite_code = invite_response.get_json()['invite_code']

    # Register regular user
    register_response = client.post('/api/register', json={
        'email': 'regular_user@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    assert register_response.status_code == 201

    # Login as regular user
    login_response = client.post('/api/login', json={
        'email': 'regular_user@test.com',
        'password': 'test_password'
    })
    assert login_response.status_code == 200
    user_token = login_response.get_json()['access_token']

    # Try to create invite code as regular user
    response = client.post('/api/invite',
        headers={'Authorization': f'Bearer {user_token}'}
    )
    assert response.status_code == 403
    data = response.get_json()
    assert 'message' in data
    assert data['message'] == 'Unauthorized'

def test_register_with_used_invite_code(client, admin_headers):
    # Create invite code as admin
    invite_response = client.post('/api/invite', headers=admin_headers)
    assert invite_response.status_code == 201, f"Failed to create invite: {invite_response.get_json()}"
    invite_code = invite_response.get_json()['invite_code']

    # Register first user
    register_response = client.post('/api/register', json={
        'email': 'user1@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    assert register_response.status_code == 201

    # Try to register second user with same invite code
    response = client.post('/api/register', json={
        'email': 'user2@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'message' in data
    assert data['message'] == 'Invalid invite code'