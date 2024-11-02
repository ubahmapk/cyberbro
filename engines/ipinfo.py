import requests
import json

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

# Load API key and proxy URL from secrets.json file
with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("ipinfo")
    proxy = data.get("proxy_url")
    PROXIES = { 'http': proxy, 'https': proxy }

def query_ipinfo(ip):
    """
    Queries the IP information from the ipinfo.io API.
    Args:
        ip (str): The IP address to query.
    Returns:
        dict: A dictionary containing the extracted information with the following keys:
            - ip (str): The IP address.
            - geolocation (str): The geolocation in the format "city - region".
            - country (str): The country of the IP address.
            - hostname (str): The hostname associated with the IP address.
            - asn (str): The autonomous system number (ASN) or organization.
        None: If the response does not contain the 'ip' key.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the HTTP request.
        ValueError: If the response cannot be parsed as JSON.
    """
    # Construct the URL for the IP info API
    url = f"https://ipinfo.io/{ip}/json?token={API_KEY}"
    
    # Make a GET request to the IP info API with proxies and SSL verification disabled
    response = requests.get(url, proxies=PROXIES, verify=False)
    
    # Parse the JSON response
    data = response.json()
    
    # Check if the response contains 'ip' key
    if 'ip' in data:
        # Extract relevant information from the response
        ip = data.get("ip", "Unknown")
        hostname = data.get("hostname", "Unknown")
        city = data.get("city", "Unknown")
        region = data.get("region", "Unknown")
        asn = data.get("org", "Unknown")
        country = data.get("country", "Unknown")
        
        # Return the extracted information in a dictionary
        return {"ip": ip, "geolocation": f"{city} - {region}", "country": country, "hostname": hostname, "asn": asn}
    
    # Return None if 'ip' key is not in the response
    return None
