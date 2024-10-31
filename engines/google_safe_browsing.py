from utils import *

import requests
import json

# Disable SSL warning
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("google_safe_browsing")

def query_google_safe_browsing(observable):
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    # Déterminer le type d'observable et construire la requête
    threat_entries = []
    
    # Vérification de l'URL
    if identify_observable_type(observable) == "URL":
        threat_entries.append({"url": observable})
    
    # Vérification des FQDN
    elif identify_observable_type(observable) == "FQDN":
        threat_entries.append({"url": f"http://{observable}"})  # Ou https selon votre besoin
    
    # Vérification des IP
    elif identify_observable_type(observable) in ["IPv4", "IPv6"]:
        threat_entries.append({"url": f"http://{observable}"})  # Traitement comme une URL

    # Créer le corps de la requête
    body = {
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED"
            ],
            "platformTypes": ["ALL"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }

    response = requests.post(url, json=body)
    data = response.json()

    if 'matches' in data:
        return {"threat_found": "Threat found", "details": data['matches']}
    else:
        return {"threat_found": "No threat found", "details": None}
