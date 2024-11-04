# Cyberbro

A good alternative for CyberGordon

# Getting Started

* To get started, clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

## Edit the config file

```
cp secrets-sample.json secrets.json
```

* Fill values (including proxy if needed) in the `secrets.json` file.

```json
{
    "virustotal": "token_here",
    "abuseipdb": "token_here",
    "ipinfo": "token_here",
    "google_safe_browsing": "token_here",
    "proxy_url": "",
    "spur_email": "spur_email_here",
    "spur_password": "spur_password_here"
}
```

# Launch the app

```
python3 app.py
```

```
* Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with watchdog (windowsapi)
 * Debugger is active!
 * Debugger PIN: 820-969-550
```

* Go to http://127.0.0.1:5000 and Enjoy.

![image](https://github.com/user-attachments/assets/fe5950cb-a839-4e60-9632-f8892b564fe3)

![image](https://github.com/user-attachments/assets/b3ec1258-94dd-4f51-bf8f-c52b80702bac)

# Use docker

```bash
docker compose up -d
```

> Don't forget to edit the `secrets.json` before building the image.
