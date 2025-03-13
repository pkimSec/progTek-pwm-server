import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
# Use fewer workers (2-4 is usually sufficient)
workers = int(os.environ.get('GUNICORN_WORKERS', '3'))
threads = 2
worker_class = 'sync'
worker_timeout = 60
keepalive = 2