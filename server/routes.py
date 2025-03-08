# server/routes.py
from flask import Blueprint, request, jsonify, current_app, session
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    current_user, get_jwt
)
from server.models import db, User
from datetime import datetime, timezone, UTC
import uuid
import logging

from server.api_session import create_api_session

api = Blueprint('api', __name__)

@api.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Missing email or password'}), 400

        user = User.query.filter_by(email=data['email'], is_active=True).first()
        current_app.logger.info(f"Login attempt for user: {data['email']}")

        if user and user.check_password(data['password']):
            # Create token
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims={'role': user.role}
            )
            
            # Initialize session
            session.clear()
            session['user_id'] = user.id
            session['created_at'] = datetime.now(UTC).isoformat()
            session['role'] = user.role
            session.permanent = True
            
            # Create API session token for non-browser clients
            session_token = create_api_session(user.id)
            
            current_app.logger.info(f"Login successful for user ID: {user.id}")
            
            # Return both the JWT token and session token
            return jsonify({
                'access_token': access_token,
                'role': user.role,
                'user_id': user.id,
                'session_token': session_token  # Add this to the response
            }), 200

        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout and clear session"""
    try:
        session.clear()
        current_app.logger.info(f"User logged out: {get_jwt_identity()}")
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/invite', methods=['POST'])
@jwt_required()
def create_invite():
    try:
        # Get user ID from token
        user_id = get_jwt_identity()
        current_app.logger.info(f"Processing invite request for user ID: {user_id}")
        
        # Convert string ID back to integer and get user
        current_user = db.session.get(User, int(user_id))
        if not current_user or current_user.role != 'admin':
            return jsonify({'message': 'Unauthorized'}), 403

        # Create invite code
        invite_code = str(uuid.uuid4())
        new_invite = User(
            email=None,
            password_hash=None,
            role='user',
            invite_code=invite_code,
            is_active=False
        )
        
        db.session.add(new_invite)
        db.session.commit()
        
        current_app.logger.info(f"Created invite code: {invite_code}")
        return jsonify({'invite_code': invite_code}), 201

    except Exception as e:
        current_app.logger.error(f"Error in create_invite: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/debug/token', methods=['GET'])
@jwt_required()
def debug_token():
    user_id = get_jwt_identity()
    jwt_data = get_jwt()
    current_app.logger.info(f"Debug token data - User ID: {user_id}, JWT: {jwt_data}")
    current_app.logger.info(f"Session data: {session}")
    current_app.logger.info(f"user_id in session: {session.get('user_id')}")
    
    user = db.session.get(User, int(user_id))
    return jsonify({
        'user_id': user_id,
        'email': user.email if user else None,
        'role': jwt_data.get('role'),
        'jwt_data': jwt_data
    }), 200

@api.route('/api/debug/session', methods=['GET'])
def debug_session():
    from flask import session
    return jsonify({
        'session_data': dict(session),
        'session_headers': dict(request.headers),
        'cookies': request.cookies
    })

@api.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No input data provided'}), 400

        if not all(k in data for k in ['email', 'password', 'invite_code']):
            return jsonify({'message': 'Missing required fields'}), 400

        invite = User.query.filter_by(
            invite_code=data['invite_code'],
            is_active=False,
            email=None
        ).first()
        
        if not invite:
            return jsonify({'message': 'Invalid invite code'}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400

        # Generate vault key salt during registration
        vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        invite.email = data['email']
        invite.set_password(data['password'])
        invite.is_active = True
        invite.vault_key_salt = vault_key_salt
        
        db.session.commit()
        current_app.logger.info(f"Registered new user: {data['email']}")
        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/invites', methods=['GET'])
@jwt_required()
def list_invites():
    """List all invite codes (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({'message': 'Admin role required'}), 403
            
        # Get all invite codes
        invites = User.query.filter(
            User.invite_code.isnot(None)
        ).all()
        
        # Convert to list of dicts
        invite_list = []
        for user in invites:
            invite_data = {
                'code': user.invite_code,
                'is_used': user.email is not None,
                'email': user.email,
                'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None
            }
            invite_list.append(invite_data)
        
        return jsonify({
            'invite_codes': invite_list
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List invites error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/invites/<invite_code>', methods=['DELETE'])
@jwt_required()
def deactivate_invite(invite_code):
    """Deactivate an invite code (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({'message': 'Admin role required'}), 403
            
        # Find the invite code
        user = User.query.filter_by(invite_code=invite_code).first()
        if not user:
            return jsonify({'message': 'Invite code not found'}), 404
            
        # Check if already used
        if user.email is not None:
            return jsonify({'message': 'Cannot deactivate used invite code'}), 400
            
        # Delete the user record with the invite code
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'message': 'Invite code deactivated successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Deactivate invite error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500