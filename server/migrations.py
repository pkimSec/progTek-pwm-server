from flask_migrate import Migrate
from server.app import create_app
from server.models import db

app = create_app()
migrate = Migrate(app, db)

if __name__ == '__main__':
    # This file can be run for migration management
    print("Run Flask migration commands with:")
    print("flask db init/migrate/upgrade")