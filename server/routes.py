# server/routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    current_user, get_jwt
)
from server.models import db, User
import uuid
import logging

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
            # Create token with string identity
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims={'role': user.role}
            )
            current_app.logger.info(f"Login successful for user ID: {user.id}")
            return jsonify({
                'access_token': access_token,
                'role': user.role,
                'user_id': user.id
            }), 200

        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
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
    
    user = db.session.get(User, int(user_id))
    return jsonify({
        'user_id': user_id,
        'email': user.email if user else None,
        'role': jwt_data.get('role'),
        'jwt_data': jwt_data
    }), 200

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

        invite.email = data['email']
        invite.set_password(data['password'])
        invite.is_active = True
        
        db.session.commit()
        current_app.logger.info(f"Registered new user: {data['email']}")
        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500