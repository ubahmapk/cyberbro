from utils import *

import requests
import json
import time
import base64

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

with open("secrets.json") as f:
    data = json.load(f)
    API_KEY = data.get("shodan")
    proxy = data.get("proxy_url")
    PROXIES = {'http': proxy, 'https': proxy}

def query_shodan(observable):
    time.sleep(3)
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + API_KEY
    }
    url = 'https://api.shodan.io/shodan/host/' + observable
    try:
        response = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
        if response.status_code == 200:
            data = response.json()
            data["link"] = "https://www.shodan.io/host/" + observable
            return data
        else:
            return None
    except Exception as e:
        print(e)
        return None