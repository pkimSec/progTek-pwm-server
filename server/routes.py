# server/routes.py
from datetime import datetime, timezone, UTC
import uuid
import base64
import os
import platform
import psutil

from flask import Blueprint, request, jsonify, current_app, session
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)

from server.models import db, User
from server.api_session import create_api_session, requires_api_session, api_sessions

api = Blueprint('api', __name__)

# ---------- LOGIN/LOGOUT ----------

@api.route('/login', methods=['POST'])
def login():
    """User login"""
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
    """User Logout and clear session"""
    try:
        # Get user ID from token
        user_id = get_jwt_identity()
        
        # Clear Flask session
        session.clear()
        
        # Get the session token from header
        session_token = request.headers.get('X-API-Session-Token')
        
        # Log all headers for debugging
        current_app.logger.info(f"Logout request - Headers: {dict(request.headers)}")
        
        # Check if we have a session token and remove from api_sessions
        if session_token and session_token in api_sessions:
            current_app.logger.info(f"Removing API session: {session_token}")
            del api_sessions[session_token]
        else:
            # Fall back to removing sessions by user ID
            sessions_to_remove = []
            for token, data in api_sessions.items():
                if str(data.get('user_id')) == user_id:
                    sessions_to_remove.append(token)
                    
            for token in sessions_to_remove:
                current_app.logger.info(f"Removing user {user_id} session: {token}")
                del api_sessions[token]
            
        current_app.logger.info(f"User {user_id} logged out successfully")
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        return jsonify({'message': 'Internal server error'}), 500

# ---------- DEBUG ----------

# ---------- ADMIN ROUTES / SYSTEM INFORMATION ----------

@api.route('/admin/system', methods=['GET'])
@jwt_required()
@requires_api_session
def get_system_info():
    """Get system information (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({'message': 'Admin role required'}), 403
            
        # Get basic system info
        system_info = {
            'status': 'online',
            'server_time': datetime.now(UTC).isoformat(),
            'hostname': platform.node(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'start_time': getattr(current_app, 'start_time', None)
        }
        
        # Add process info if psutil is available
        try:
            process = psutil.Process(os.getpid())
            
            # Get process creation time as a datetime object
            create_time_float = process.create_time()
            create_time = datetime.fromtimestamp(create_time_float)
            
            # Calculate uptime in seconds
            uptime_seconds = (datetime.now() - create_time).total_seconds()
            
            system_info.update({
                'cpu_percent': process.cpu_percent(),
                'memory_usage': process.memory_info().rss,
                'uptime_seconds': uptime_seconds
            })
        except (ImportError, AttributeError) as e:
            current_app.logger.warning(f"psutil metrics error: {str(e)}")
            
        return jsonify(system_info), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting system info: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/admin/sessions', methods=['GET'])
@jwt_required()
@requires_api_session
def get_active_sessions():
    """Get all active sessions (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({'message': 'Admin role required'}), 403
            
        # Get all sessions from the api_sessions dictionary
        all_sessions = []
        for session_token, session_data in api_sessions.items():
            # Get user info
            user_id = session_data.get('user_id')
            user = db.session.get(User, user_id) if user_id else None
            
            session_info = {
                'session_token': session_token,
                'user_id': user_id,
                'email': user.email if user else 'Unknown',
                'role': user.role if user else 'Unknown',
                'created_at': session_data.get('created_at').isoformat() if session_data.get('created_at') else None,
                'last_activity': session_data.get('last_activity', session_data.get('created_at')).isoformat() 
                    if session_data.get('last_activity') or session_data.get('created_at') else None
            }
            all_sessions.append(session_info)
            
        return jsonify({'sessions': all_sessions}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting active sessions: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/admin/sessions/<session_token>', methods=['DELETE'])
@jwt_required()
@requires_api_session
def terminate_session(session_token):
    """Terminate a session (admin only)"""
    try:
        # Check admin permission
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({'message': 'Admin role required'}), 403
            
        # Check if session exists
        if session_token not in api_sessions:
            return jsonify({'message': 'Session not found'}), 404
            
        # Remove session
        del api_sessions[session_token]
        
        return jsonify({'message': 'Session terminated successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error terminating session: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# ---------- REGISTRATION / INVITES ----------

@api.route('/register', methods=['POST'])
def register():
    """Register a new user with an invite code"""
    try:
        current_app.logger.info("Processing registration request")
        data = request.get_json()
        current_app.logger.info(f"Registration data received: {data}")
        
        if not data:
            current_app.logger.error("No input data provided")
            return jsonify({'message': 'No input data provided'}), 400

        if not all(k in data for k in ['email', 'password', 'invite_code']):
            current_app.logger.error("Missing required fields")
            return jsonify({'message': 'Missing required fields'}), 400

        # Find the invite by code
        invite = User.query.filter_by(
            invite_code=data['invite_code'],
            is_active=False,
            email=None
        ).first()
        
        if not invite:
            current_app.logger.error(f"Invalid invite code: {data['invite_code']}")
            return jsonify({'message': 'Invalid invite code'}), 400

        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            current_app.logger.error(f"Email already registered: {data['email']}")
            return jsonify({'message': 'Email already registered'}), 400

        # Generate vault key salt during registration
        vault_key_salt = base64.b64encode(os.urandom(32)).decode('utf-8')
        current_app.logger.info(f"Generated vault key salt for new user")
        
        # Update the invite record to become a user
        invite.email = data['email']
        invite.set_password(data['password'])
        invite.is_active = True
        invite.vault_key_salt = vault_key_salt
        
        db.session.commit()
        current_app.logger.info(f"Registered new user: {data['email']}")
        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@api.route('/invite', methods=['POST'])
@jwt_required()
def create_invite():
    """Create an invite code for a new user"""
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

# ---------- SERVER PING ----------

@api.route('/ping', methods=['GET'])
def ping():
    """Simple health check endpoint that doesn't require authentication"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'message': 'Server is running'
    }), 200