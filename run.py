# run.py
from server.app import create_app

app = create_app()

if __name__ == '__main__':
    import os
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    else:
        # For production, use Gunicorn through command line
        print("In production mode, please run with gunicorn:")
        print("gunicorn -c gunicorn_config.py 'run:app'")