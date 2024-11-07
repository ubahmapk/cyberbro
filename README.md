# Cyberbro

A good alternative for CyberGordon

# Features

* Check if an observable (IP, hash, domain, URL) is malicious using VirusTotal, AbuseIPDB, IPInfo, Spur.us and Google Safe Browsing.
* Comprehensive report with search and filter features (type, country, risk, detection, proxy/VPN).
* Uses multithreading to speed up the process (articially limited with `time.sleep()` because of free API usage).
* Performs a reverse DNS lookup.
* Provides the ability to export the results to a CSV file and an Excel file.
* Uses a proxy if needed.

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

* To get API keys, refer to the official documentation of the services.
* Everything is free as long as you are authenticated (restrictions may be applied).

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

# Use docker

```bash
docker compose up -d
```

> Don't forget to edit the `secrets.json` before building the image.

# Screenshots

![image](https://github.com/user-attachments/assets/b0243594-2d22-4505-810c-9e3df09dc617)
![image](https://github.com/user-attachments/assets/f6658546-ef5d-4c47-9367-b1443eab4b6b)

![image](https://github.com/user-attachments/assets/d68d82e7-f1ab-45c1-b0a2-ad9a7e4681bc)
![image](https://github.com/user-attachments/assets/9c0648bc-c475-4df6-81c4-17be068aa26a)

# Security

Disclaimer: this is a development server, not intended for production.

# License

```
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
```
