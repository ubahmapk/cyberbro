import requests
import json

# Disable SSL warning
requests.packages.urllib3.disable_warnings()

# Load API key and proxy settings from secrets.json
with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("google_safe_browsing")
    proxy = data.get("proxy_url")
    PROXIES = { 'http': proxy, 'https': proxy }

def query_google_safe_browsing(observable, observable_type):
    """
    Queries the Google Safe Browsing API to check if the given observable is associated with any threats.
    Args:
        observable (str): The observable to be checked. It can be a URL, Fully Qualified Domain Name (FQDN), or an IP address.
    Returns:
        dict: A dictionary containing the result of the query. The dictionary has the following keys:
            - "threat_found" (str): Indicates whether a threat was found ("Threat found" or "No threat found").
            - "details" (list or None): If a threat was found, this contains the details of the threats. Otherwise, it is None.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the network request.
        ValueError: If the observable type is not recognized.
    """
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    # Determine the type of observable and construct the request
    threat_entries = []
    
    # Check if the observable is a URL
    if observable_type == "URL":
        threat_entries.append({"url": observable})
    
    # Check if the observable is a Fully Qualified Domain Name (FQDN)
    elif observable_type == "FQDN":
        threat_entries.append({"url": f"http://{observable}"})  # Or https depending on your need
    
    # Check if the observable is an IP address
    elif observable_type in ["IPv4", "IPv6"]:
        threat_entries.append({"url": f"http://{observable}"})  # Treat as a URL

    # Create the request body
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

    # Send the request to Google Safe Browsing API
    response = requests.post(url, json=body, proxies=PROXIES, verify=False)
    data = response.json()

    # Check if any threats were found
    if 'matches' in data:
        return {"threat_found": "Threat found", "details": data['matches']}
    else:
        return {"threat_found": "No threat found", "details": None}
