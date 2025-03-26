# server/category_routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from server.models import db, Category
from server.api_session import requires_api_session
from server.security import requires_secure_transport

category_api = Blueprint('category_api', __name__)

@category_api.route('/categories', methods=['GET'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def list_categories():
    """Get all categories for the current user"""
    try:
        user_id = int(get_jwt_identity())
        
        categories = Category.query.filter_by(user_id=user_id).all()
        return jsonify({
            'categories': [category.to_dict() for category in categories]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error listing categories: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@category_api.route('/categories', methods=['POST'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def create_category():
    """Create a new category"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'message': 'Category name is required'}), 400
            
        # Create new category
        category = Category(
            user_id=user_id,
            name=data['name'],
            parent_id=data.get('parent_id')
        )
        
        db.session.add(category)
        db.session.commit()
        
        return jsonify({
            'message': 'Category created successfully',
            'category': category.to_dict()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Error creating category: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@category_api.route('/categories/<int:category_id>', methods=['GET'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def get_category(category_id):
    """Get a specific category"""
    try:
        user_id = int(get_jwt_identity())
        
        category = Category.query.filter_by(id=category_id, user_id=user_id).first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
            
        return jsonify(category.to_dict()), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting category: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@category_api.route('/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def update_category(category_id):
    """Update a category"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'No update data provided'}), 400
            
        category = Category.query.filter_by(id=category_id, user_id=user_id).first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
            
        # Update fields
        if 'name' in data:
            category.name = data['name']
            
        if 'parent_id' in data:
            # Prevent circular references
            if data['parent_id'] == category_id:
                return jsonify({'message': 'Category cannot be its own parent'}), 400
                
            category.parent_id = data['parent_id']
            
        db.session.commit()
        
        return jsonify({
            'message': 'Category updated successfully',
            'category': category.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error updating category: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@category_api.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
@requires_api_session
@requires_secure_transport
def delete_category(category_id):
    """Delete a category"""
    try:
        user_id = int(get_jwt_identity())
        
        category = Category.query.filter_by(id=category_id, user_id=user_id).first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
            
        # Delete the category
        db.session.delete(category)
        db.session.commit()
        
        return jsonify({
            'message': 'Category deleted successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error deleting category: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500