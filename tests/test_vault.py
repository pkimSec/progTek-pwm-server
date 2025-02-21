# tests/test_vault.py
import pytest
import json
from server.models import User, PasswordEntry, UserVaultMeta, db
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

def test_vault_setup(client, user_headers):
    """Test vault initialization"""
    # Test missing master password
    response = client.post('/api/vault/setup',
        headers=user_headers,
        json={}
    )
    assert response.status_code == 400
    assert 'Master password required' in response.get_json()['message']
    
    # Test successful setup
    response = client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    assert response.status_code == 201
    assert 'Vault initialized successfully' in response.get_json()['message']
    
    # Verify metadata was created
    user = User.query.filter_by(email='test_user@test.com').first()
    meta = UserVaultMeta.query.filter_by(user_id=user.id).first()
    assert meta is not None
    assert meta.key_salt is not None
    
    # Test duplicate setup
    response = client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    assert response.status_code == 400
    assert 'Vault already initialized' in response.get_json()['message']

def test_create_password_entry(client, user_headers):
    """Test creating password entries"""
    # Setup vault first
    client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    
    # Test missing required fields
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json={'name': 'Test Entry'}
    )
    assert response.status_code == 400
    assert 'Missing required fields' in response.get_json()['message']
    
    # Test successful creation
    entry_data = {
        'name': 'Test Entry',
        'username': 'testuser',
        'password': 'secretpass',
        'website': 'https://example.com',
        'notes': 'Test notes',
        'master_password': 'vault_password'
    }
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=entry_data
    )
    assert response.status_code == 201
    data = response.get_json()
    assert 'id' in data
    assert 'Entry created successfully' in data['message']
    
    # Verify entry was created
    user = User.query.filter_by(email='test_user@test.com').first()
    entry = PasswordEntry.query.filter_by(user_id=user.id).first()
    assert entry is not None
    assert entry.name == 'Test Entry'
    
    # Verify encryption
    encrypted_data = json.loads(entry.encrypted_password)
    assert 'iv' in encrypted_data
    assert 'ciphertext' in encrypted_data
    assert 'salt' in encrypted_data

def test_list_password_entries(client, user_headers):
    """Test listing password entries"""
    # Setup vault and create entries
    client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    
    # Create two entries
    for i in range(2):
        client.post('/api/vault/entries',
            headers=user_headers,
            json={
                'name': f'Entry {i}',
                'username': f'user{i}',
                'password': f'pass{i}',
                'master_password': 'vault_password'
            }
        )
    
    # Test listing entries
    response = client.get('/api/vault/entries',
        headers=user_headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'entries' in data
    entries = data['entries']
    assert len(entries) == 2
    
    # Verify entry data
    entry = entries[0]
    assert 'id' in entry
    assert 'name' in entry
    assert 'created_at' in entry
    assert 'updated_at' in entry
    # Verify no sensitive data is returned
    assert 'password' not in entry
    assert 'encrypted_password' not in entry

def test_get_password_entry(client, user_headers):
    """Test retrieving specific password entries"""
    # Setup vault and create entry
    client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    
    entry_data = {
        'name': 'Test Entry',
        'username': 'testuser',
        'password': 'secretpass',
        'website': 'https://example.com',
        'notes': 'Test notes',
        'master_password': 'vault_password'
    }
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=entry_data
    )
    entry_id = response.get_json()['id']
    
    # Test missing master password
    response = client.get(f'/api/vault/entries/{entry_id}',
        headers=user_headers
    )
    assert response.status_code == 400
    assert 'Master password required' in response.get_json()['message']
    
    # Test with wrong master password
    headers = user_headers.copy()
    headers['X-Master-Password'] = 'wrong_password'
    response = client.get(f'/api/vault/entries/{entry_id}',
        headers=headers
    )
    assert response.status_code == 400
    assert 'Decryption failed' in response.get_json()['message']
    
    # Test successful retrieval
    headers = user_headers.copy()
    headers['X-Master-Password'] = 'vault_password'
    response = client.get(f'/api/vault/entries/{entry_id}',
        headers=headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == entry_data['name']
    assert data['username'] == entry_data['username']
    assert data['password'] == entry_data['password']
    assert data['website'] == entry_data['website']
    assert data['notes'] == entry_data['notes']

def test_update_password_entry(client, user_headers):
    """Test updating password entries"""
    # Setup vault and create entry
    client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json={
            'name': 'Original Entry',
            'username': 'olduser',
            'password': 'oldpass',
            'master_password': 'vault_password'
        }
    )
    entry_id = response.get_json()['id']
    
    # Test missing master password
    response = client.put(f'/api/vault/entries/{entry_id}',
        headers=user_headers,
        json={'name': 'Updated Entry'}
    )
    assert response.status_code == 400
    assert 'Master password required' in response.get_json()['message']
    
    # Test successful update
    update_data = {
        'name': 'Updated Entry',
        'username': 'newuser',
        'password': 'newpass',
        'website': 'https://updated.com',
        'notes': 'Updated notes',
        'master_password': 'vault_password'
    }
    
    response = client.put(f'/api/vault/entries/{entry_id}',
        headers=user_headers,
        json=update_data
    )
    assert response.status_code == 200
    assert 'Entry updated successfully' in response.get_json()['message']
    
    # Verify update
    headers = user_headers.copy()
    headers['X-Master-Password'] = 'vault_password'
    response = client.get(f'/api/vault/entries/{entry_id}',
        headers=headers
    )
    data = response.get_json()
    assert data['name'] == update_data['name']
    assert data['username'] == update_data['username']
    assert data['password'] == update_data['password']
    assert data['website'] == update_data['website']
    assert data['notes'] == update_data['notes']

def test_delete_password_entry(client, user_headers):
    """Test deleting password entries"""
    # Setup vault and create entry
    client.post('/api/vault/setup',
        headers=user_headers,
        json={'master_password': 'vault_password'}
    )
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json={
            'name': 'Test Entry',
            'username': 'testuser',
            'password': 'testpass',
            'master_password': 'vault_password'
        }
    )
    entry_id = response.get_json()['id']
    
    # Test deleting non-existent entry
    response = client.delete('/api/vault/entries/99999',
        headers=user_headers
    )
    assert response.status_code == 404
    assert 'Entry not found' in response.get_json()['message']
    
    # Test successful deletion
    response = client.delete(f'/api/vault/entries/{entry_id}',
        headers=user_headers
    )
    assert response.status_code == 200
    assert 'Entry deleted successfully' in response.get_json()['message']
    
    # Verify deletion
    user = User.query.filter_by(email='test_user@test.com').first()
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    assert entry is None

def test_crypto_functions():
    """Test the crypto utility functions directly"""
    # Test key derivation
    password = "test_password"
    key1, salt1 = VaultCrypto.derive_key(password)
    key2, _ = VaultCrypto.derive_key(password)  # Generate new salt
    
    assert len(key1) == VaultCrypto.KEY_LENGTH
    assert len(salt1) == VaultCrypto.SALT_LENGTH
    assert key1 != key2  # Different salts should produce different keys
    
    key3, _ = VaultCrypto.derive_key(password, salt1)
    assert key1 == key3  # Same password and salt should produce same key
    
    # Test encryption/decryption
    test_data = {
        'username': 'testuser',
        'password': 'testpass',
        'notes': 'test notes'
    }
    
    encrypted = VaultCrypto.encrypt_data(test_data, key1)
    assert 'iv' in encrypted
    assert 'ciphertext' in encrypted
    
    decrypted = VaultCrypto.decrypt_data(encrypted, key1)
    assert decrypted == test_data
    
    # Test decryption with wrong key
    wrong_key, _ = VaultCrypto.derive_key("wrong_password")
    with pytest.raises(ValueError):
        VaultCrypto.decrypt_data(encrypted, wrong_key)