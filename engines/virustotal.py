from utils import *

import requests
import json
import time

# Disable SSL warning in case of proxies that break SSL
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("virustotal")
    proxy = data.get("proxy_url")
    PROXIES = {'http': proxy, 'https': proxy}

def query_virustotal(observable):
    # API rate slowing down bro
    time.sleep(3)
    headers = {"x-apikey": API_KEY}

    # Detect the observable type and adjust the API URL
    observable_type = identify_observable_type(observable)
    if observable_type in ["IPv4", "IPv6"]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable}"
    elif observable_type == "FQDN":
        url = f"https://www.virustotal.com/api/v3/domains/{observable}"
    else:  # Assume any other observable is a file hash
        url = f"https://www.virustotal.com/api/v3/files/{observable}"

    response = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
    data = response.json()

    if 'data' in data:
        attributes = data['data']['attributes']
        
        # Utiliser last_analysis_stats pour le ratio de détection
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        total_malicious = last_analysis_stats.get('malicious', 0)
        total_engines = sum(last_analysis_stats.values())

        # Établir le ratio de détection
        detection_ratio = f"{total_malicious}/{total_engines}" if total_engines > 0 else "0/0"

        link = f"https://www.virustotal.com/gui/{'file' if 'files' in url else 'ip-address' if 'ip_addresses' in url else 'domain'}/{observable}/detection"
        
        # Remplacement de 'verdict' par 'community_score'
        community_score = attributes.get('reputation', 'Unknown')

        return {"detection_ratio": detection_ratio, "total_malicious": total_malicious, "link": link, "community_score": community_score}
    
    return {"detection_ratio": "0/0", "total_malicious": 0, "link": None, "community_score": 0}
