from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
import os

def ensure_db_exists(app):
    """Ensure the PostgreSQL database exists"""
    try:
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        if not database_exists(engine.url):
            create_database(engine.url)
            app.logger.info(f"Created database: {engine.url.database}")
        return True
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        return False