import requests
import json

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("ipinfo")
    proxy = data.get("proxy_url")
    PROXIES = { 'http': proxy, 'https': proxy }

def query_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}/json?token={API_KEY}"
    response = requests.get(url, proxies=PROXIES, verify=False)
    data = response.json()
    
    if 'ip' in data:
        hostname = data.get("hostname", "Unknown")
        city = data.get("city", "Unknown")
        region = data.get("region", "Unknown")
        asn = data.get("org", "Unknown")
        country = data.get("country", "Unknown")
        return {"geolocation": f"{city} - {region}", "country": country, "hostname": hostname, "asn": asn}
    return None
