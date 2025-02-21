# server/vault_routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from server.models import db, PasswordEntry, UserVaultMeta, User, PasswordEntryVersion
from server.crypto import UserVault, VaultCrypto
from datetime import datetime, UTC
import json, base64, os

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

@vault_api.route('/vault/salt', methods=['GET'])
@jwt_required()
def get_vault_salt():
    """Get user's vault key salt for client-side key derivation"""
    try:
        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        
        if not user.vault_key_salt:
            # Generate salt if not exists
            user.vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
            db.session.commit()
            
        return jsonify({
            'salt': user.vault_key_salt
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting vault salt: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries', methods=['POST'])
@jwt_required()
def create_entry():
    """
    Create new password entry.
    Expects encrypted data from client.
    """
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or 'encrypted_data' not in data:
            return jsonify({'message': 'Missing encrypted data'}), 400
            
        entry = PasswordEntry(
            user_id=user_id,
            encrypted_data=data['encrypted_data']
        )
        
        db.session.add(entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Entry created successfully',
            'id': entry.id,
            'created_at': entry.created_at.isoformat()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Create entry error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries', methods=['GET'])
@jwt_required()
def list_entries():
    """List all encrypted entries for the user"""
    try:
        user_id = int(get_jwt_identity())
        
        entries = PasswordEntry.query.filter_by(user_id=user_id).all()
        return jsonify({
            'entries': [{
                'id': entry.id,
                'encrypted_data': entry.encrypted_data,
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
    """Get specific encrypted entry"""
    try:
        user_id = int(get_jwt_identity())
        
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        return jsonify({
            'id': entry.id,
            'encrypted_data': entry.encrypted_data,
            'created_at': entry.created_at.isoformat(),
            'updated_at': entry.updated_at.isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get entry error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>', methods=['PUT'])
@jwt_required()
def update_entry(entry_id):
    """Update encrypted entry"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or 'encrypted_data' not in data:
            return jsonify({'message': 'Missing encrypted data'}), 400
            
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
        
        # Create version before updating
        entry.create_version()
        
        # Update entry
        entry.encrypted_data = data['encrypted_data']
        entry.updated_at = datetime.now(UTC)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Entry updated successfully',
            'version': entry.current_version
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Update entry error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>', methods=['DELETE'])
@jwt_required()
def delete_entry(entry_id):
    """Delete entry"""
    try:
        user_id = int(get_jwt_identity())
        
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

@vault_api.route('/vault/entries/<int:entry_id>/versions', methods=['GET'])
@jwt_required()
def list_entry_versions(entry_id):
    """List available versions of an entry"""
    try:
        user_id = int(get_jwt_identity())
        
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        versions = entry.versions.limit(2).all()
        return jsonify({
            'versions': [{
                'id': version.id,
                'encrypted_data': version.encrypted_data,
                'created_at': version.created_at.isoformat()
            } for version in versions]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List versions error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@vault_api.route('/vault/entries/<int:entry_id>/versions/<int:version_id>', methods=['GET'])
@jwt_required()
def get_entry_version(entry_id, version_id):
    """Get a specific version of an entry"""
    try:
        user_id = int(get_jwt_identity())
        
        entry = PasswordEntry.query.filter_by(id=entry_id, user_id=user_id).first()
        if not entry:
            return jsonify({'message': 'Entry not found'}), 404
            
        version = PasswordEntryVersion.query.filter_by(
            id=version_id,
            entry_id=entry_id
        ).first()
        if not version:
            return jsonify({'message': 'Version not found'}), 404
            
        return jsonify({
            'id': version.id,
            'encrypted_data': version.encrypted_data,
            'created_at': version.created_at.isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get version error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500