import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_ip_quality_score(ip, API_KEY, PROXIES):
    """
    Queries the IP Quality Score API for information about the given IP address.
    
    Args:
        ip (str): The IP address to query.
    
    Returns:
        dict: The response data from the API if successful, otherwise None.
    """
    # Construct the URL for the IP quality score API
    url = f"https://ipqualityscore.com/api/json/ip/{API_KEY}/{ip}"
    
    try:
        # Make a GET request to the IP quality score API with proxies and SSL verification disabled
        response = requests.get(url, proxies=PROXIES, verify=False)
        
        # Parse the JSON response
        data = response.json()
        
        # Check if the response contains 'success' key and it is True
        if 'success' in data and data['success'] == True:
            data["link"] = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"
            return data
        
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None