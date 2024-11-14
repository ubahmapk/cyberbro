# Cyberbro

A good private alternative for Cybergordon (custom API).

# Features

* Check if an observable (IP, hash, domain, URL) is malicious using VirusTotal, AbuseIPDB, IPInfo, Spur.us, IP Quality Score, MDE, Google Safe Browsing, Shodan...
* Comprehensive report with search and filter features (type, country, risk, detection, proxy/VPN).
* Uses multithreading to speed up the process (articially limited with `time.sleep()` because of free API usage).
* Performs a reverse DNS lookup.
* Provides the ability to export the results to a CSV file and an Excel file.
* Checks if the observable has been seen on the Microsoft Defender for Endpoint (MDE) platform (your tenant).
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
    "mde_tenant_id": "tenant_here",
    "mde_client_id": "client_id_here",
    "mde_client_secret": "client_secret_here",
    "ip_quality_score": "token_here",
    "shodan": "token_here"
}
```

* To get API keys, refer to the official documentation of the services.
* MDE is NOT free, you can skip it if you don't have an account (unchecked by default).

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

![Capture d’écran_14-11-2024_93625_cyberbro stan local](https://github.com/user-attachments/assets/8b5962ae-df66-437d-9aa7-43c17062b3d6)

![Capture d’écran_14-11-2024_93636_cyberbro stan local](https://github.com/user-attachments/assets/77f3e9fb-6f80-44bb-a8db-abc5c1c376b1)

![Capture d’écran_14-11-2024_93554_cyberbro stan local](https://github.com/user-attachments/assets/eced18ef-cab1-4056-9f59-323cf91bef3c)

![Capture d’écran_14-11-2024_93537_cyberbro stan local](https://github.com/user-attachments/assets/3afe3b1f-a7c3-4c7b-bb32-42ebf6a3f1a6)


# Security

Disclaimer: this is a development server, not intended for production.

# API and third-party services

* [VirusTotal](https://developers.virustotal.com/v3.0/reference)
* [AbuseIPDB](https://docs.abuseipdb.com/)
* [IPInfo](https://ipinfo.io/developers)
* [Google Safe Browsing](https://developers.google.com/safe-browsing)
* [IP Quality Score](https://www.ipqualityscore.com/)
* [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-for-endpoint-api)
* [Shodan](https://developer.shodan.io/)
* [Spur.us](https://spur.us/)

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

