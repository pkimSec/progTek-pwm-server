# server/user_routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from server.models import db, User
from server.session import requires_active_session
from server.api_session import requires_api_session
from server.security import requires_secure_transport
from datetime import datetime
import logging

user_api = Blueprint('user_api', __name__)

def is_admin(jwt_data):
    """Check if user has admin role based on JWT claims"""
    return jwt_data.get('role') == 'admin'

@user_api.route('/users', methods=['GET'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def list_users():
    """List all users (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if not is_admin(jwt_data):
            return jsonify({'message': 'Admin role required'}), 403
            
        # Get all users
        users = User.query.all()
        
        # Return user list with limited fields for security
        return jsonify({
            'users': [{
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None
            } for user in users]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List users error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@user_api.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def get_user(user_id):
    """Get specific user details (admin only or self)"""
    try:
        # Get JWT data
        jwt_data = get_jwt()
        jwt_user_id = int(get_jwt_identity())
        
        # Check permission - allow admins or users viewing themselves
        if not is_admin(jwt_data) and jwt_user_id != user_id:
            return jsonify({'message': 'Permission denied'}), 403
            
        # Get user
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Return user details
        return jsonify({
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get user error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@user_api.route('/users/<int:user_id>', methods=['PATCH'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def update_user(user_id):
    """Update user details (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if not is_admin(jwt_data):
            return jsonify({'message': 'Admin role required'}), 403
            
        # Get user
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Get update data
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No update data provided'}), 400
            
        # Update fields
        updates = {}
        
        # Update role
        if 'role' in data:
            role = data['role']
            if role not in ['admin', 'user']:
                return jsonify({'message': 'Invalid role'}), 400
                
            # Prevent removing the last admin
            if user.role == 'admin' and role != 'admin':
                admin_count = User.query.filter_by(role='admin', is_active=True).count()
                if admin_count <= 1:
                    return jsonify({'message': 'Cannot remove last admin user'}), 400
                    
            user.role = role
            updates['role'] = role
            
        # Update active status
        if 'is_active' in data:
            is_active = bool(data['is_active'])
            
            # Prevent disabling the last admin
            if user.role == 'admin' and user.is_active and not is_active:
                admin_count = User.query.filter_by(role='admin', is_active=True).count()
                if admin_count <= 1:
                    return jsonify({'message': 'Cannot disable last admin user'}), 400
                    
            user.is_active = is_active
            updates['is_active'] = is_active
            
        # If no valid updates
        if not updates:
            return jsonify({'message': 'No valid updates provided'}), 400
            
        # Save changes
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'updates': updates
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Update user error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@user_api.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        jwt_user_id = int(get_jwt_identity())
        
        if not is_admin(jwt_data):
            return jsonify({'message': 'Admin role required'}), 403
            
        # Prevent self-deletion
        if jwt_user_id == user_id:
            return jsonify({'message': 'Cannot delete your own account'}), 400
            
        # Get user
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Prevent deleting the last admin
        if user.role == 'admin' and user.is_active:
            admin_count = User.query.filter_by(role='admin', is_active=True).count()
            if admin_count <= 1:
                return jsonify({'message': 'Cannot delete last admin user'}), 400
                
        # Delete the user
        # Note: In a real application, you might want to handle associated data
        # like password entries, etc.
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User deleted successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete user error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500