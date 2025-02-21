# tests/test_versions.py
import json
import base64
from server.models import db, PasswordEntry, PasswordEntryVersion

def test_entry_versioning(client, user_headers):
    """Test version creation when updating entries"""
    # Create initial entry
    initial_data = {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'initial-data').decode('utf-8')
        })
    }
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=initial_data
    )
    assert response.status_code == 201
    entry_id = response.get_json()['id']
    
    # Update entry multiple times
    for i in range(3):  # Create more than max versions
        updated_data = {
            'encrypted_data': json.dumps({
                'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
                'data': base64.b64encode(f'update-{i}'.encode()).decode('utf-8')
            })
        }
        
        response = client.put(f'/api/vault/entries/{entry_id}',
            headers=user_headers,
            json=updated_data
        )
        assert response.status_code == 200
    
    # Check versions
    response = client.get(f'/api/vault/entries/{entry_id}/versions',
        headers=user_headers
    )
    assert response.status_code == 200
    versions = response.get_json()['versions']
    
    # Should only have 2 versions (current state not included)
    assert len(versions) == 2

def test_get_specific_version(client, user_headers):
    """Test retrieving specific versions"""
    # Create and update an entry
    initial_data = {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'initial-data').decode('utf-8')
        })
    }
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=initial_data
    )
    entry_id = response.get_json()['id']
    
    # Update once to create a version
    updated_data = {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'updated-data').decode('utf-8')
        })
    }
    
    client.put(f'/api/vault/entries/{entry_id}',
        headers=user_headers,
        json=updated_data
    )
    
    # Get versions
    response = client.get(f'/api/vault/entries/{entry_id}/versions',
        headers=user_headers
    )
    assert response.status_code == 200
    versions = response.get_json()['versions']
    
    # Get specific version
    version_id = versions[0]['id']
    response = client.get(f'/api/vault/entries/{entry_id}/versions/{version_id}',
        headers=user_headers
    )
    assert response.status_code == 200
    version_data = response.get_json()
    
    # Verify version data
    assert version_data['encrypted_data'] == initial_data['encrypted_data']

def test_version_access_control(client, user_headers):
    """Test version access control"""
    # Create entry
    initial_data = {
        'encrypted_data': json.dumps({
            'iv': base64.b64encode(b'test-iv-123456').decode('utf-8'),
            'data': base64.b64encode(b'initial-data').decode('utf-8')
        })
    }
    
    response = client.post('/api/vault/entries',
        headers=user_headers,
        json=initial_data
    )
    entry_id = response.get_json()['id']
    
    # Try to access non-existent entry versions
    response = client.get('/api/vault/entries/99999/versions',
        headers=user_headers
    )
    assert response.status_code == 404
    
    # Try to access non-existent version
    response = client.get(f'/api/vault/entries/{entry_id}/versions/99999',
        headers=user_headers
    )
    assert response.status_code == 404