import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_ipquery(ip, PROXIES):
    """
    Queries the IP information from the ipquery.io API.
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
    try:
        # Construct the URL for the IP Query API
        url = f"https://api.ipquery.io/{ip}"
        
        # Make a GET request to the IP Query API with proxies and SSL verification disabled
        response = requests.get(url, proxies=PROXIES, verify=False)
        
        # Parse the JSON response
        data = response.json()
        
        # Check if the response contains 'ip' key
        if 'ip' in data:
            # Extract relevant information from the response
            ip = data.get("ip", "Unknown")
            city = data.get("location", {}).get("city", "Unknown")
            region = data.get("location", {}).get("state", "Unknown")
            country_code = data.get("location", {}).get("country_code", "Unknown")
            country_name = data.get("location", {}).get("country", "Unknown")
            isp = data.get("isp", {}).get("isp", "Unknown")
            asn = data.get("isp", {}).get("asn", "Unknown")
            is_vpn = data.get("risk", {}).get("is_vpn", False)
            is_tor = data.get("risk", {}).get("is_tor", False)
            is_proxy = data.get("risk", {}).get("is_proxy", False)
            risk_score = data.get("risk", {}).get("risk_score", "Unknown")
            
            # Return the extracted information in a dictionary
            return {
                "ip": ip,
                "geolocation": f"{city}, {region}",
                "country_code": country_code,
                "country_name": country_name,
                "isp": isp,
                "asn": asn,
                "is_vpn": is_vpn,
                "is_tor": is_tor,
                "is_proxy": is_proxy,
                "risk_score": risk_score,
                "link": f"https://api.ipquery.io/{ip}"
            }

    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None
