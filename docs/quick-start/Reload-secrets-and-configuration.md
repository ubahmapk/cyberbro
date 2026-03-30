## With docker

### The container cyberbro is running
1. ```docker exec -it cyberbro bash```
2. ```root@container:/app# nano .env```
3. ```root@container:/app# service supervisor restart```
4. ```root@container:/app# exit```
5. Then go to http://127.0.0.1:5000 and use Cyberbro.

### The container cyberbro is not running
1. Edit `.env` with the updated values.
2. ```docker compose up --build --force-recreate -d```
3. Then go to http://127.0.0.1:5000 and use Cyberbro.

## Without docker
1. Edit `.env` (or exported environment variables) with the updated values.
2. Restart your `gunicorn` instance or start `supervisord` e.g. `service supervisord restart`
3. Then go to http://127.0.0.1:5000 and use Cyberbro.
