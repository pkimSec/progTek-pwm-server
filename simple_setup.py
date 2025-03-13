def setup_database():
    """Set up database directly without migrations"""
    from server.app import create_app
    from server.models import db
    
    app = create_app()
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("Database tables created successfully!")
            return True
        except Exception as e:
            print(f"Error setting up database: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    setup_database()