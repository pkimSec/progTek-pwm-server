# tests/test_vault.py
import pytest, json, base64
from server.models import User, PasswordEntry, db
from server.crypto import UserVault, VaultCrypto

@pytest.fixture
def user_headers(client):
    """Create a regular user and get auth headers"""
    # First get admin token to create invite
    response = client.post('/api/login', json={
        'email': 'test_admin@localhost',
        'password': 'admin_password'
    })
    admin_token = response.get_json()['access_token']
    
    # Create invite code
    invite_response = client.post('/api/invite', 
        headers={'Authorization': f'Bearer {admin_token}'}
    )
    invite_code = invite_response.get_json()['invite_code']
    
    # Register new user
    client.post('/api/register', json={
        'email': 'test_user@test.com',
        'password': 'test_password',
        'invite_code': invite_code
    })
    
    # Login as new user
    response = client.post('/api/login', json={
        'email': 'test_user@test.com',
        'password': 'test_password'
    })
    token = response.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def mock_encrypted_entry():
    """Create a mock encrypted entry for testing"""
    return {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'encrypted-test-data').decode('utf-8')
        })
    }

def test_get_vault_salt(client, user_headers):
    """Test getting vault salt for key derivation"""
    # First request should generate a new salt
    response = client.get('/api/vault/salt', headers=user_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert 'salt' in data
    first_salt = data['salt']
    
    # Second request should return the same salt
    response = client.get('/api/vault/salt', headers=user_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data['salt'] == first_salt
    
    # Verify salt is properly stored
    user = User.query.filter_by(email='test_user@test.com').first()
    assert user.vault_key_salt == first_salt

def test_create_password_entry(client, user_headers, mock_encrypted_entry):
    """Test creating encrypted password entries"""
    # Test missing encrypted data
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json={}
    )
    assert response.status_code == 400
    assert 'Missing encrypted data' in response.get_json()['message']
    
    # Test successful creation
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=mock_encrypted_entry
    )
    assert response.status_code == 201
    data = response.get_json()
    assert 'id' in data
    assert 'created_at' in data
    
    # Verify entry was created with encrypted data
    user = User.query.filter_by(email='test_user@test.com').first()
    entry = PasswordEntry.query.filter_by(user_id=user.id).first()
    assert entry is not None
    assert entry.encrypted_data == mock_encrypted_entry['encrypted_data']

def test_list_password_entries(client, user_headers, mock_encrypted_entry):
    """Test listing encrypted entries"""
    # Create two entries
    entries = []
    for i in range(2):
        response = client.post('/api/vault/entries',
            headers=user_headers,
            json=mock_encrypted_entry
        )
        assert response.status_code == 201
        entries.append(response.get_json()['id'])
    
    # Test listing entries
    response = client.get('/api/vault/entries',
        headers=user_headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'entries' in data
    assert len(data['entries']) == 2
    
    # Verify entry data
    entry = data['entries'][0]
    assert 'id' in entry
    assert 'encrypted_data' in entry
    assert 'created_at' in entry
    assert 'updated_at' in entry
    assert entry['encrypted_data'] == mock_encrypted_entry['encrypted_data']

def test_get_password_entry(client, user_headers, mock_encrypted_entry):
    """Test retrieving specific encrypted entries"""
    # Create an entry
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=mock_encrypted_entry
    )
    entry_id = response.get_json()['id']
    
    # Test getting non-existent entry
    response = client.get(f'/api/vault/entries/99999',
        headers=user_headers
    )
    assert response.status_code == 404
    
    # Test successful retrieval
    response = client.get(f'/api/vault/entries/{entry_id}',
        headers=user_headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == entry_id
    assert data['encrypted_data'] == mock_encrypted_entry['encrypted_data']

def test_update_password_entry(client, user_headers, mock_encrypted_entry):
    """Test updating encrypted entries"""
    # Create an entry
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=mock_encrypted_entry
    )
    entry_id = response.get_json()['id']
    
    # Test missing encrypted data
    response = client.put(f'/api/vault/entries/{entry_id}',
        headers=user_headers,
        json={}
    )
    assert response.status_code == 400
    assert 'Missing encrypted data' in response.get_json()['message']
    
    # Test updating non-existent entry
    response = client.put('/api/vault/entries/99999',
        headers=user_headers,
        json=mock_encrypted_entry
    )
    assert response.status_code == 404
    
    # Create updated encrypted data
    updated_data = {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'new-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'new-encrypted-data').decode('utf-8')
        })
    }
    
    # Test successful update
    response = client.put(f'/api/vault/entries/{entry_id}',
        headers=user_headers,
        json=updated_data
    )
    assert response.status_code == 200
    assert 'Entry updated successfully' in response.get_json()['message']
    
    # Verify update using db.session.get
    entry = db.session.get(PasswordEntry, entry_id)
    assert entry.encrypted_data == updated_data['encrypted_data']

def test_delete_password_entry(client, user_headers, mock_encrypted_entry):
    """Test deleting encrypted entries"""
    # Create an entry
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=mock_encrypted_entry
    )
    entry_id = response.get_json()['id']
    
    # Test deleting non-existent entry
    response = client.delete('/api/vault/entries/99999',
        headers=user_headers
    )
    assert response.status_code == 404
    
    # Test successful deletion
    response = client.delete(f'/api/vault/entries/{entry_id}',
        headers=user_headers
    )
    assert response.status_code == 200
    assert 'Entry deleted successfully' in response.get_json()['message']
    
    # Verify deletion using db.session.get
    entry = db.session.get(PasswordEntry, entry_id)
    assert entry is None