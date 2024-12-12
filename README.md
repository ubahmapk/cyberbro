# Cyberbro

A simple application that extracts your IoCs from garbage input and checks their reputation using multiple services. \
Inspired by [Cybergordon](https://cybergordon.com/) and [IntelOwl](https://github.com/intelowlproject/IntelOwl).

This project aims to provide a simple and efficient way to check the reputation of your observables using multiple services, 
without having to deploy a **complex** solution.

![GitHub stars](https://img.shields.io/github/stars/stanfrbd/cyberbro?style=social)
![GitHub issues](https://img.shields.io/github/issues/stanfrbd/cyberbro)
![License](https://img.shields.io/github/license/stanfrbd/cyberbro)
![example branch parameter](https://github.com/stanfrbd/cyberbro/actions/workflows/jobs.yml/badge.svg)

![cyberbro_gh](https://github.com/user-attachments/assets/d82a021c-a199-4f07-ab26-7af8e1b650a0)

# Features

* **Effortless Input Handling**: Paste raw logs, IoCs, or fanged IoCs, and let our regex parser do the rest.
* **Multi-Service Reputation Checks**: Verify observables (IP, hash, domain, URL) across multiple services like VirusTotal, AbuseIPDB, IPInfo, Spur.us, IP Quality Score, MDE, Google Safe Browsing, Shodan, Abusix, Phishtank, ThreatFox, Github, Google...
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

* Obtain API keys from the official documentation of each service.
* Note: Microsoft Defender for Endpoint (MDE) is a paid service and can be skipped if you don't have an account (unchecked by default).

> **Warning:** You can modify the configuration via the GUI at [http://127.0.0.1:5000/config](http://127.0.0.1:5000/config). This endpoint is disabled by default for security reasons, as it is not protected. To enable it, set `app.config['CONFIG_PAGE_ENABLED'] = True` at the beginning of `app.py`. 
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

![image-analysis](https://github.com/user-attachments/assets/7104a3c5-5574-4ccf-8889-891abb746e5d)

![image-history](https://github.com/user-attachments/assets/ccecdbbd-e561-4e04-9b48-0c36fc059e6c)

![image-stats](https://github.com/user-attachments/assets/f044d711-50b4-4384-b164-077730f42184)

</details>

![image-base](https://github.com/user-attachments/assets/9f789edf-ad41-4269-8cee-47331481999b)

# Security

**Disclaimer**: this is still a development server, not intended for production. \
Some misconfigurations may lead to **security issues**.

# API and third-party services

* [VirusTotal](https://developers.virustotal.com/v3.0/reference)
* [AbuseIPDB](https://docs.abuseipdb.com/)
* [IPInfo](https://ipinfo.io/developers)
* [Google Safe Browsing](https://developers.google.com/safe-browsing)
* [IP Quality Score](https://www.ipqualityscore.com/)
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

