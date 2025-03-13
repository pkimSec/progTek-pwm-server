#!/bin/bash
set -e

# Wait for PostgreSQL to become available
until python -c "import psycopg2; psycopg2.connect(dbname='$DB_NAME', user='$DB_USER', password='$DB_PASSWORD', host='$DB_HOST')" &>/dev/null; do
  echo "PostgreSQL is unavailable - sleeping"
  sleep 1
done

echo "PostgreSQL is up - continuing"

# Initialize the database with a single process
python init_db.py

# Start the application with normal worker count
exec gunicorn -c gunicorn_config.py 'run:app'