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
    Queries Microsoft Defender for Endpoint for information about a given observable.
    Parameters:
    observable (str): The observable to query. This can be a hash (MD5, SHA1, SHA256), IP address (IPv4, IPv6), 
                      fully qualified domain name (FQDN), or URL.
    Returns:
    dict: A dictionary containing the response data from Microsoft Defender for Endpoint, including a link to 
          the observable's details on the Microsoft Defender Security Center. If the observable is a file hash, 
          additional file information is included (issuer, signer, isValidCertificate, filePublisher, 
          fileProductName, determinationType, determinationValue). Returns None if the request fails.
    """

    jwt_token = read_token() or get_token()

    headers = {"Authorization": "Bearer " + jwt_token}

    # Detect the observable type and adjust the API URL
    observable_type = identify_observable_type(observable)
    file_info_url = None
    if observable_type in ["MD5", "SHA1", "SHA256"]:
        url = f"https://api.securitycenter.microsoft.com/api/files/{observable}/stats"
        file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{observable}"
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
    
    if file_info_url:
        file_info_response = requests.get(file_info_url, headers=headers, proxies=PROXIES, verify=False)
        file_info = file_info_response.json()

    if response.status_code == 200:
        data = response.json()
        data["link"] = link
        if file_info_url:
            data["issuer"] = file_info.get("issuer", "Unknown")
            data["signer"] = file_info.get("signer", "Unknown")
            data["isValidCertificate"] = file_info.get("isValidCertificate", "Unknown")
            data["filePublisher"] = file_info.get("filePublisher", "Unknown")
            data["fileProductName"] = file_info.get("fileProductName", "Unknown")
            data["determinationType"] = file_info.get("determinationType", "Unknown")
            data["determinationValue"] = file_info.get("determinationValue", "Unknown")
        # print(data)
        return data
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

    