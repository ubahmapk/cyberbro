import requests
import json
import time
import base64

# Disable SSL warning in case of proxies that break SSL
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("virustotal")
    proxy = data.get("proxy_url")
    PROXIES = {'http': proxy, 'https': proxy}

def query_virustotal(observable, observable_type):
    """
    Queries the VirusTotal API for information about a given observable.
    Args:
        observable (str): The observable to query. This can be an IP address (IPv4 or IPv6), 
                          a fully qualified domain name (FQDN), a URL, or a file hash.
    Returns:
        dict: A dictionary containing the following keys:
            - detection_ratio (str): The ratio of malicious detections to total engines.
            - total_malicious (int): The total number of engines that flagged the observable as malicious.
            - link (str): A link to the VirusTotal GUI for the observable.
            - community_score (int or str): The community reputation score of the observable, or 'Unknown' if not available.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the HTTP request.
        KeyError: If the expected data is not found in the API response.
    """
    # API rate limiting
    time.sleep(3)
    headers = {"x-apikey": API_KEY}

    # Adjust the URL based on the observable type
    if observable_type in ["IPv4", "IPv6"]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable}"
        link = f"https://www.virustotal.com/gui/ip-address/{observable}/detection"
    elif observable_type == "FQDN":
        url = f"https://www.virustotal.com/api/v3/domains/{observable}"
        link = f"https://www.virustotal.com/gui/domain/{observable}/detection"
    elif observable_type == "URL":
        encoded_url = base64.urlsafe_b64encode(observable.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
    else:  # Assume any other observable is a file hash
        url = f"https://www.virustotal.com/api/v3/files/{observable}"
        link = f"https://www.virustotal.com/gui/file/{observable}/detection"

    response = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
    data = response.json()
    # print(data)

    if 'data' in data:
        attributes = data['data']['attributes']
        
        # Use last_analysis_stats for detection ratio
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        total_malicious = last_analysis_stats.get('malicious', 0)
        total_engines = sum(last_analysis_stats.values())

        # Establish the detection ratio
        detection_ratio = f"{total_malicious}/{total_engines}" if total_engines > 0 else "0/0"
        
        # Replace 'verdict' with 'community_score'
        community_score = attributes.get('reputation', 'Unknown')

        return {"detection_ratio": detection_ratio, "total_malicious": total_malicious, "link": link, "community_score": community_score}
    
    return {"detection_ratio": "0/0", "total_malicious": 0, "link": f"https://www.virustotal.com/gui/search/{observable}", "community_score": 0}
