import requests
import pycountry

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_ipinfo(ip, API_KEY, PROXIES):
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

    if "bogon" in data:
        return {"ip": ip, "geolocation": "", "country_code": "", "country_name": "", "hostname": "Private IP", "asn": "BOGON", "link": f"https://ipinfo.io/{ip}"}
    
    # Check if the response contains 'ip' key
    if 'ip' in data:
        # Extract relevant information from the response
        ip = data.get("ip", "Unknown")
        hostname = data.get("hostname", "Unknown")
        city = data.get("city", "Unknown")
        region = data.get("region", "Unknown")
        asn = data.get("org", "Unknown")
        country_code = data.get("country", "Unknown")
        country_name = pycountry.countries.get(alpha_2=country_code).name
        
        # Return the extracted information in a dictionary
        return {"ip": ip, "geolocation": f"{city}, {region}", "country_code": country_code, "country_name": country_name, "hostname": hostname, "asn": asn, "link": f"https://ipinfo.io/{ip}"}
    
    # Return None if 'ip' key is not in the response
    return None
