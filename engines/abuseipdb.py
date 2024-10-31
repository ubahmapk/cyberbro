import requests
import json

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("abuseipdb")
    proxy = data.get("proxy_url")
    PROXIES = { 'http': proxy, 'https': proxy }

def query_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip}
    response = requests.get(url, headers=headers, params=params, proxies=PROXIES, verify=False)
    data = response.json()
    
    if 'data' in data:
        reports = data['data'].get('totalReports', 0)
        risk_score = data['data'].get('abuseConfidenceScore', 0)
        link = f"https://www.abuseipdb.com/check/{ip}"
        return {"reports": reports, "risk_score": risk_score, "link": link}
    return None
