from stem import Signal
from stem.control import Controller
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import time
import json
import socket

ua = UserAgent()

# Disable SSL warning in case of proxy like Zscaler which breaks SSL...
requests.packages.urllib3.disable_warnings()

# Load API key and proxy URL from secrets.json file
with open("secrets.json") as f:
    data = json.load(f)
    proxy = data.get("proxy_url")
    PROXIES = {'http': proxy, 'https': proxy}

def is_tor_running():
    try:
        with socket.create_connection(("127.0.0.1", 9051), timeout=2):
            return True
    except socket.error:
        return False

TOR_RUNNING = is_tor_running()

if TOR_RUNNING:
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
else:
    proxies = PROXIES

def get_new_identity():
    if TOR_RUNNING:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()  # Authentication using cookie
            controller.signal(Signal.NEWNYM)

def get_spur(ip):
    """
    Retrieves information about the given IP address from the spur.us website.

    This function makes an HTTP GET request to the spur.us website to fetch context information about the provided IP address.
    If the TOR network is running, it waits for a second before making the request. The function parses the HTML response to
    extract the anonymity status of the IP address from the page title.

    Args:
        ip (str): The IP address to retrieve information for.

    Returns:
        dict: A dictionary containing the link to the spur.us context page and the anonymity status of the IP address.
              The dictionary has the following structure:
              {
                  "link": str,      # The URL to the spur.us context page for the given IP address.
                  "tunnels": str    # The anonymity status of the IP address.
              }
        None: If an error occurs during the request or parsing process.
    """
    try:
        if TOR_RUNNING:
            #get_new_identity()
            time.sleep(1)
        spur_url = f"https://spur.us/context/{ip}"
        spur_data = requests.get(spur_url, proxies=proxies, verify=False, headers={"User-Agent": ua.random})
        # print(spur_data.text)

        soup = BeautifulSoup(spur_data.text, 'html.parser')
        title_tag = soup.title

        if title_tag is not None:
            title_text = title_tag.get_text()

            if "(" in title_text and ")" in title_text:
                content = title_text.split("(")[1].split(")")[0].strip()
            else:
                content = "Not Anonymous"
        else:
            if TOR_RUNNING:
                time.sleep(5)
                get_new_identity()
                get_spur(ip)
        return {"link": f"https://spur.us/context/{ip}", "tunnels": content}
    except Exception as e:
        print(f"Error occurred: {e}")
        return None