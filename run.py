# run.py
from server.app import create_app

if __name__ == '__main__':
    """
    Main entry point for the password manager server.
    
    This script creates and runs the Flask application.
    The server will start on 0.0.0.0:5000 by default.
    
    Note:
    - Debug mode is enabled for development (disable in production)
    - The server listens on all interfaces (0.0.0.0)
    - First run will create an admin user (see console output for credentials)
    """
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)