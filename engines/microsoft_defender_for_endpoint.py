from utils import *

import json
import requests
import jwt


# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    tenant_id = data.get("mde_tenant_id")
    client_id = data.get("mde_client_id")
    client_secret = data.get("mde_client_secret")
    proxy = data.get("proxy_url")
    PROXIES = { 'http': proxy, 'https': proxy }

def check_token_validity(token):
    try:
        if jwt.decode(token, verify=False):
            return True
        else:
            return False
    except Exception:
        return False

def read_token():
    try:
        with open("mde_token.txt", "r") as f:
            token = f.read()
        if check_token_validity(token):
            return token
        else:
            print("Invalid token")
            return None
    except Exception:
        return None

def get_token():

    url = "https://login.microsoftonline.com/{}/oauth2/token".format(tenant_id)

    resourceAppIdUri = 'https://api.securitycenter.microsoft.com'

    body = {
        'resource' : resourceAppIdUri,
        'client_id' : client_id,
        'client_secret' : client_secret,
        'grant_type' : 'client_credentials'
    }

    try:
        response = requests.post(url, data=body, proxies=PROXIES, verify=False)
        json_response = json.loads(response.content)
    except Exception as err:
        print("Error: " + str(err))
    try:
        aad_token = json_response["access_token"]
        with open("mde_token.txt", "w") as f:
            f.write(aad_token)
    except:
        print("Error: Unable to retrieve token")
        aad_token = "invalid"
    return aad_token

def query_microsoft_defender_for_endpoint(observable):
    """
    Queries the Microsoft Defender for Endpoint API for information about a given observable.
    Args:
        observable (str): The observable to query. This can be an IP address (IPv4 or IPv6), 
                          a fully qualified domain name (FQDN), a URL, or a file hash.
    Returns:
        dict: A dictionary containing the following keys:
            - detection_ratio (str): The ratio of malicious detections to total engines.
            - total_malicious (int): The total number of engines that flagged the observable as malicious.
            - link (str): A link to the Microsoft Defender for Endpoint GUI for the observable.
            - community_score (int or str): The community reputation score of the observable, or 'Unknown' if not available.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the HTTP request.
        KeyError: If the expected data is not found in the API response.
    """

    jwt_token = read_token() or get_token()

    headers = {"Authorization": "Bearer " + jwt_token}

    # Detect the observable type and adjust the API URL
    observable_type = identify_observable_type(observable)
    if observable_type in ["MD5", "SHA1", "SHA256"]:
        url = f"https://api.securitycenter.microsoft.com/api/files/{observable}"
        link = f"https://securitycenter.microsoft.com/file/{observable}"
    elif observable_type in ["IPv4", "IPv6"]:
        url = f"https://api.securitycenter.microsoft.com/api/ips/{observable}/stats"
        link = f"https://securitycenter.microsoft.com/ip/{observable}/overview"
    elif observable_type == "FQDN":
        url = f"https://api.securitycenter.microsoft.com/api/domains/{observable}/stats"
        link = f"https://securitycenter.microsoft.com/domains?urlDomain={observable}"
    elif observable_type == "URL":
        extracted_domain = observable.split('/')[2]
        url = f"https://api.securitycenter.microsoft.com/api/domains/{extracted_domain}/stats"
        link = f"https://securitycenter.microsoft.com/url?url={observable}"

    response = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
    if response.status_code == 200:
        data = response.json()
        data["link"] = link
        print(data)
        return data
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

    