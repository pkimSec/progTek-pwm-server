# server/vault_routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from server.models import db, PasswordEntry, User, UserVaultMeta
from server.crypto import UserVault, VaultCrypto
from datetime import datetime, UTC
import json
import base64

vault_api = Blueprint('vault_api', __name__)

@vault_api.route('/vault/setup', methods=['POST'])
@jwt_required()
def setup_vault():
    """Initialize user's vault with master password"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or 'master_password' not in data:
            return jsonify({'message': 'Master password required'}), 400
            
        # Check if vault already exists
        if UserVaultMeta.query.filter_by(user_id=user_id).first():
            return jsonify({'message': 'Vault already initialized'}), 400
            
        # Create new vault
        vault = UserVault(user_id, data['master_password'])
        
        # Store vault metadata
        meta = UserVaultMeta(
            user_id=user_id,
            key_salt=base64.b64encode(vault.salt).decode('utf-8')
        )
        db.session.add(meta)
        db.session.commit()
        
        return jsonify({'message': 'Vault initialized successfully'}), 201
        
    except Exception as e:
        current_app.logger.error(f"Vault setup error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries', methods=['POST'])
@jwt_required()
def create_entry():
    """Create new password entry"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or not all(k in data for k in ['name', 'username', 'password', 'master_password']):
            return jsonify({'message': 'Missing required fields'}), 400
            
        # Get vault metadata
        vault_meta = UserVaultMeta.query.filter_by(user_id=user_id).first()
        if not vault_meta:
            return jsonify({'message': 'Vault not initialized'}), 400
            
        # Create vault instance
        vault = UserVault(user_id, data['master_password'])
        
        # Prepare entry data for encryption
        entry_data = {
            'username': data['username'],
            'password': data['password'],
            'website': data.get('website', ''),
            'notes': data.get('notes', '')
        }
        
        # Encrypt entry
        encrypted_data = vault.encrypt_entry(entry_data)
        
        # Create entry with all required fields
        entry = PasswordEntry(
            user_id=user_id,
            name=data['name'],
            username=data['username'],  # Store username in plaintext for searching
            encrypted_password=json.dumps(encrypted_data),
            website=data.get('website', ''),  # Store website in plaintext for searching
            notes=data.get('notes', '')  # Store notes in plaintext for searching
        )
        
        db.session.add(entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Entry created successfully',
            'id': entry.id,
            'name': entry.name,
            'username': entry.username,
            'website': entry.website
        }), 201
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Create entry error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries', methods=['GET'])
@jwt_required()
def list_entries():
    """List all password entries (without passwords)"""
    try:
        user_id = int(get_jwt_identity())
        
        entries = PasswordEntry.query.filter_by(user_id=user_id).all()
        return jsonify({
            'entries': [{
                'id': entry.id,
                'name': entry.name,
                'username': entry.username,
                'website': entry.website,
                'created_at': entry.created_at.isoformat(),
                'updated_at': entry.updated_at.isoformat()
            } for entry in entries]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List entries error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>', methods=['GET'])
@jwt_required()
def get_entry(entry_id):
    """Get specific password entry with decrypted data"""
    try:
        user_id = int(get_jwt_identity())
        master_password = request.headers.get('X-Master-Password')
        
        if not master_password:
            return jsonify({'message': 'Master password required'}), 400
            
        # Get entry and verify ownership
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        # Decrypt entry
        encrypted_data = json.loads(entry.encrypted_password)
        decrypted_data = UserVault.decrypt_entry(encrypted_data, master_password)
        
        return jsonify({
            'id': entry.id,
            'name': entry.name,
            'username': decrypted_data['username'],
            'password': decrypted_data['password'],
            'website': entry.website,
            'notes': entry.notes,
            'created_at': entry.created_at.isoformat(),
            'updated_at': entry.updated_at.isoformat()
        }), 200
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Get entry error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>', methods=['PUT'])
@jwt_required()
def update_entry(entry_id):
    """Update password entry"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or 'master_password' not in data:
            return jsonify({'message': 'Master password required'}), 400
            
        # Get entry and verify ownership
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        # Create vault instance
        vault = UserVault(user_id, data['master_password'])
        
        # Get current decrypted data
        current_encrypted = json.loads(entry.encrypted_password)
        current_data = UserVault.decrypt_entry(current_encrypted, data['master_password'])
        
        # Update entry data
        entry_data = {
            'username': data.get('username', current_data['username']),
            'password': data.get('password', current_data['password']),
            'website': data.get('website', entry.website),
            'notes': data.get('notes', entry.notes)
        }
        
        # Encrypt updated data
        encrypted_data = vault.encrypt_entry(entry_data)
        
        # Update entry
        entry.name = data.get('name', entry.name)
        entry.username = entry_data['username']  # Update plaintext username
        entry.encrypted_password = json.dumps(encrypted_data)
        entry.website = entry_data['website']
        entry.notes = entry_data['notes']
        entry.updated_at = datetime.now(UTC)
        
        db.session.commit()
        
        return jsonify({'message': 'Entry updated successfully'}), 200
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Update entry error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>', methods=['DELETE'])
@jwt_required()
def delete_entry(entry_id):
    """Delete password entry"""
    try:
        user_id = int(get_jwt_identity())
        
        # Get entry and verify ownership
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        db.session.delete(entry)
        db.session.commit()
        
        return jsonify({'message': 'Entry deleted successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete entry error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500