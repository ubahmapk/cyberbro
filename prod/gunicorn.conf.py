from utils.config import Secrets, get_config

secrets: Secrets = get_config()
bind = f"{secrets.flask_bind}:{secrets.flask_port}"
workers = secrets.gunicorn_workers_count
threads = secrets.gunicorn_threads_count
timeout = secrets.gunicorn_timeout
