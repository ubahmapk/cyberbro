import requests
import argparse
import json
import time
import jwt
import csv

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    spur_email = data.get("spur_email")
    spur_password = data.get("spur_password")
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
        with open("token.txt", "r") as f:
            token = f.read()
        if check_token_validity(token):
            return token
        else:
            print("invalid token")
            return None
    except Exception:
        return None

def get_token():
    url_token_request = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyBj3TdbafNunMDVPI2iKGOQr6f1AwCY1AI"
    request_data = {
            "email": spur_email,
            "password": spur_password,
            "returnSecureToken": True
        }

    headers_token_request = {
            "Host": "www.googleapis.com",
            "Content-Type": "application/json",
            "X-Client-Version": "Chrome/JsCore/8.10.1/FirebaseCore-web",
            "Sec-Ch-Ua": "\"Not(A:Brand\";v=\"24\", \"Chromium\";v=\"122\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36",
            "Sec-Ch-Ua-Platform": "\"Linux\"",
            "Accept": "*/*",
            "Origin": "https://app.spur.us",
            "X-Client-Data": "CKDtygE=",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://app.spur.us/",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Priority": "u=1, i"
    }

    token_response = requests.post(url_token_request, json=request_data, headers=headers_token_request, proxies=PROXIES, verify=False)

    if token_response.status_code == 200:
        # Extraction du token JWT de la réponse JSON
        token_response_json = token_response.json()
        jwt_token = token_response_json.get("idToken", None)
        if jwt_token:
            #print("Token JWT obtenu avec succès :", jwt_token)
            with open("token.txt", "w") as f:
                f.write(jwt_token)
            return jwt_token
        else:
            print("Impossible de trouver le token JWT dans la réponse.")
            return None
    else:
        print("Échec de la requête pour obtenir le token JWT. Statut de la réponse :", token_response.status_code)
        return None

def process_ip_with_spur(ip):
    
    # API rate slowing down bro
    time.sleep(3)

    # Variables
    ip_address = ip
    jwt_token = read_token() or get_token()

    # Headers
    headers = {
        "Host": "app.spur.us",
        "Sec-Ch-Ua": "\"Not(A:Brand\";v=\"24\", \"Chromium\";v=\"122\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Authorization": f"Bearer {jwt_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Accept": "*/*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": f"https://app.spur.us/context?q={ip_address}",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Priority": "u=1, i"
    }

    # URL
    url = f"https://app.spur.us/api/v1/search/{ip_address}"

    # Requête
    response = requests.get(url, proxies=PROXIES, headers=headers, verify=False)

    # Traitement de la réponse et extraction des informations pertinentes
    if response.status_code == 200:
        data = response.json().get('data', {})
        v2 = data.get('v2', {})
        location = v2.get('location', {})
        client = v2.get('client', {})

        tunnels = ", ".join([tunnel.get("operator", "") for tunnel in v2.get("tunnels", [])])

        if tunnels == '':
            tunnels = "Not anonymous"

        return {
            "ip": v2.get("ip", ""),
            "organization": v2.get("organization", ""),
            "city": location.get("city", ""),
            "country": location.get("country", ""),
            "state": location.get("state", ""),
            "infrastructure": v2.get("infrastructure", ""),
            "risks": ", ".join(v2.get("risks", [])),
            "client_types": ", ".join(client.get("types", [])),
            "client_behaviors": ", ".join(client.get("behaviors", [])),
            "client_proxies": ", ".join(client.get("proxies", [])),
            "tunnels": tunnels
        }
    else:
        print(f"Failed to process IP {ip_address}. Status code: {response.status_code}")
        return None