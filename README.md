# Cyberbro

A simple application that extracts your IoCs from garbage input and checks their reputation using multiple services. \
Inspired by [Cybergordon](https://cybergordon.com/) and [IntelOwl](https://github.com/intelowlproject/IntelOwl).

This project aims to provide a simple and efficient way to check the reputation of your observables using multiple services, 
without having to deploy a **complex** solution.

**==> Checkout the public demo: https://demo.cyberbro.net/ <==**

![GitHub stars](https://img.shields.io/github/stars/stanfrbd/cyberbro?style=social)
[![Follow on X/Twitter](https://img.shields.io/twitter/follow/cyberbro_cti?style=social)](https://x.com/cyberbro_cti)
![GitHub issues](https://img.shields.io/github/issues/stanfrbd/cyberbro)
![License](https://img.shields.io/github/license/stanfrbd/cyberbro)
![example branch parameter](https://github.com/stanfrbd/cyberbro/actions/workflows/jobs.yml/badge.svg)

![cyberbro_gh](https://github.com/user-attachments/assets/d82a021c-a199-4f07-ab26-7af8e1b650a0)

# Features

* **Effortless Input Handling**: Paste raw logs, IoCs, or fanged IoCs, and let our regex parser do the rest.
* **Multi-Service Reputation Checks**: Verify observables (IP, hash, domain, URL) across multiple services like VirusTotal, AbuseIPDB, IPInfo, Spur.us, MDE, Google Safe Browsing, Shodan, Abusix, Phishtank, ThreatFox, Github, Google...
* **Detailed Reports**: Generate comprehensive reports with advanced search and filter options.
* **High Performance**: Leverage multithreading for faster processing.
* **Automated Observable Pivoting**: Automatically pivot on domains, URL and IP addresses using reverse DNS and RDAP.
* **Accurate Domain Info**: Retrieve precise domain information from ICANN RDAP (next generation whois).
* **Abuse Contact Lookup**: Accurately find abuse contacts for IPs, URLs, and domains.
* **Export Options**: Export results to CSV and **autofiltered well formatted** Excel files.
* **MDE Integration**: Check if observables are flagged on your Microsoft Defender for Endpoint (MDE) tenant.
* **Proxy Support**: Use a proxy if required.
* **Data Storage**: Store results in a SQLite database.
* **Analysis History**: Maintain a history of analyses with easy retrieval and search functionality.

# Getting Started - TL;DR

> [!TIP]
> If you are lazy, you need Docker. \
> Do a `git clone` ; copy `secrets-sample.json` to `secrets.json` ; `docker compose up` then go to `localhost:5000`. Yep, that's it!

# Getting Started

* To get started, clone the repository

```bash
git clone https://github.com/stanfrbd/cyberbro
cd cyberbro
```

## Edit the config file (mandatory)

```
cp secrets-sample.json secrets.json
```

> [!NOTE]
> Don't have API keys? No problem, just copy the `secrets-sample.json` to `secrets.json` and leave all like this. Be careful if a proxy is used. \
> You will be able to use **all free engines!**

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
    "shodan": "token_here"
}
```

* Obtain API keys from the official documentation of each service.
* Microsoft Defender for Endpoint (MDE) is a paid service and can be skipped if you don't have an account (unchecked by default).

> [!IMPORTANT]
> You can modify the configuration via the GUI at [http://127.0.0.1:5000/config](http://127.0.0.1:5000/config). \
> This endpoint is disabled by default for security reasons, as it is not protected. \
> To enable it, set `app.config['CONFIG_PAGE_ENABLED'] = True` at the beginning of `app.py`. \
> **This is not recommended for public or team use, as it exposes your API keys.**

# Launch the app

## Lazy and easy - use docker

```bash
docker compose up # use -d to run in background and use --build to rebuild the image
```

* Go to http://127.0.0.1:5000 and Enjoy.

> Don't forget to edit the `secrets.json` before building the image.

## The old way

* Clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

* Run the app with `gunicorn` (clean mode).

```bash
gunicorn -w 4 -t 4 -b 0.0.0.0:5000 app:app
```

* Run the app with in development mode.

```bash
python3 app.py
```

# Screenshots

<details>
<summary>See all screenshots</summary>

![image-analysis](https://github.com/user-attachments/assets/1331e340-e95d-4b0a-b487-f13b27f2e24d)

![image-history](https://github.com/user-attachments/assets/859c5f43-6da9-4a6a-8b64-23e5035df8a5)

![image-stats](https://github.com/user-attachments/assets/c4676eb5-b6de-4611-bade-e21d9e10fcf3)

</details>

![image-base](https://github.com/user-attachments/assets/5de5db84-5e9c-4a67-aa83-30894ce55779)
![image](https://github.com/user-attachments/assets/6e310bfe-ee52-4e6b-b52d-1b3a27cd2e20)

> [!CAUTION]
> This is still a development server, not intended for production. \
Some misconfigurations may lead to **security issues**.

# Cyberbro API

* The API is available at `/api/` and can be accessed via the GUI or command-line.

**There are currently two endpoints:**

* `/api/analyze` - Analyze a text and return analysis ID (JSON).
* `/api/results/<analysis_id>` - Retrieve the results of a previous analysis (JSON).

```bash
curl -X POST "http://localhost:5000/api/analyze" -H "Content-Type: application/json" -d '{"text": "20minutes.fr", "engines": ["reverse_dns", "rdap"]}'
```

```json
{
  "analysis_id": "e88de647-b153-4904-91e5-8f5c79174854",
  "link": "/results/e88de647-b153-4904-91e5-8f5c79174854"
}
```

```bash
curl "http://localhost:5000/api/results/e88de647-b153-4904-91e5-8f5c79174854"
```

```json
[
  {
    "observable": "20minutes.fr",
    "rdap": {
      "abuse_contact": "",
      "creation_date": "2001-07-11",
      "expiration_date": "2028-01-08",
      "link": "https://rdap.nic.fr/domain/20minutes.fr",
      "name_servers": [
        "ns-1271.awsdns-30.org",
        "ns-748.awsdns-29.net",
        "ns-16.awsdns-02.com",
        "ns-1958.awsdns-52.co.uk"
      ],
      "organization": "",
      "registrant": "20 MINUTES FRANCE SAS",
      "registrant_email": "0d6621ed24c26f0d32e2c4f76b507da9-679847@contact.gandi.net",
      "registrar": "GANDI",
      "update_date": "2024-11-18"
    },
    "reverse_dns": {
      "reverse_dns": [
        "13.249.9.82",
        "13.249.9.92",
        "13.249.9.83",
        "13.249.9.129"
      ]
    },
    "reversed_success": true,
    "type": "FQDN"
  }
]
```



# API and third-party services

* [VirusTotal](https://developers.virustotal.com/v3.0/reference)
* [AbuseIPDB](https://docs.abuseipdb.com/)
* [IPquery](https://ipquery.gitbook.io/ipquery-docs)
* [IPinfo](https://ipinfo.io/developers)
* [Google Safe Browsing](https://developers.google.com/safe-browsing)
* [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-for-endpoint-api)
* [Shodan](https://developer.shodan.io/)
* [Spur.us](https://spur.us/)
* [Abusix](https://abusix.com/)
* [Phishtank](https://www.phishtank.com/)
* [OpenRDAP](https://openrdap.org/api)
* [ICANN](https://lookup.icann.org/)
* [Google](https://google.com/)
* [Github](https://github.com/)
* [ThreatFox](https://threatfox.abuse.ch/api/)
* [Ioc.One](https://ioc.one/)

> [!NOTE]
> Any questions? Check the [wiki](https://github.com/stanfrbd/cyberbro/wiki) or raise an [issue](https://github.com/stanfrbd/cyberbro/issues/new)

# Special thanks

A huge thank you to all the amazing contributors who made pull requests and helped improve this project:

* [Axel](https://github.com/botlabsDev) who develops [Ioc.One](https://ioc.one/)

Your contributions are greatly appreciated!

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

