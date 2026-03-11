# ============================================
# SCREEN: change_password
# ============================================

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine

bp = Blueprint('change_password', __name__)

@bp.route('/api/change_password', methods=['POST'])
def change_password():
    '''Update password with current password verification'''
    
    # Input validation
    data = request.get_json() or {}
    user_id = data.get('user_id')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not user_id or not current_password or not new_password or not confirm_password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': 'New password and confirm password do not match'}), 400
    
    # MySQL query
    query = text("UPDATE users SET password_hash = :new_password WHERE user_id = :user_id AND password_hash = :current_password")
    
    try:
        with engine.begin() as connection:
            result = connection.execute(
                query,
                {
                    "user_id": user_id,
                    "current_password": current_password,
                    "new_password": new_password,
                },
            )
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    # Error handling
    if result.rowcount == 0:
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # Return response
    return jsonify({'message': 'Password updated successfully'}), 200
