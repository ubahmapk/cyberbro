import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_abuseipdb(ip, API_KEY, PROXIES):
    """
    Queries the AbuseIPDB API for information about a given IP address.
    Args:
        ip (str): The IP address to check.
    Returns:
        dict: A dictionary containing the following keys:
            - 'reports' (int): The total number of reports for the IP address.
            - 'risk_score' (int): The abuse confidence score for the IP address.
            - 'link' (str): A URL to the AbuseIPDB page for the IP address.
        None: If the response does not contain 'data'.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the network request.
        ValueError: If the response cannot be parsed as JSON.
    """
    try:
        # URL for the AbuseIPDB API
        url = f"https://api.abuseipdb.com/api/v2/check"
        
        # Headers including the API key
        headers = {"Key": API_KEY, "Accept": "application/json"}
        
        # Parameters including the IP address to check
        params = {"ipAddress": ip}
        
        # Make the GET request to the API
        response = requests.get(url, headers=headers, params=params, proxies=PROXIES, verify=False)
        
        # Parse the JSON response
        data = response.json()
        
        # Check if the response contains 'data'
        if 'data' in data:
            # Extract the total number of reports and the abuse confidence score
            reports = data['data'].get('totalReports', 0)
            risk_score = data['data'].get('abuseConfidenceScore', 0)
            
            # Create a link to the AbuseIPDB page for the IP address
            link = f"https://www.abuseipdb.com/check/{ip}"
            
            # Return the extracted information
            return {"reports": reports, "risk_score": risk_score, "link": link}
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None
