from stem import Signal
from stem.control import Controller
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import time

ua = UserAgent()

# Disable SSL warning in case of proxy like Zscaler which breaks SSL...
requests.packages.urllib3.disable_warnings()

def get_new_identity():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()  # Authentification par cookie
        controller.signal(Signal.NEWNYM)

# using tor and random user agent - tor must be installed and running
"""
tor config (torrc):
ControlPort 9051
CookieAuthentication 1
"""
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def get_spur(ip):
    try:
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
            time.sleep(5)
            get_new_identity()
            get_spur(ip)
        return {"link": f"https://spur.us/context/{ip}", "tunnels": content}
    except Exception as e:
        print(f"Error occurred: {e}")
        return None