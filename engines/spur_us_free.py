import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

ua = UserAgent()

# Disable SSL warning in case of proxy like Zscaler which breaks SSL...
requests.packages.urllib3.disable_warnings()

def get_spur(ip, PROXIES):
    """
    Retrieves information about the given IP address from the spur.us website.

    This function makes an HTTP GET request to the spur.us website to fetch context information about the provided IP address.
    The function parses the HTML response to extract the anonymity status of the IP address from the page title.

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
        spur_url = f"https://spur.us/context/{ip}"
        spur_data = requests.get(spur_url, proxies=PROXIES, verify=False, headers={"User-Agent": ua.random})
        # print(spur_data.text)

        soup = BeautifulSoup(spur_data.text, 'html.parser')
        title_tag = soup.title

        if title_tag is not None:
            title_text = title_tag.get_text()

            if "(" in title_text and ")" in title_text:
                content = title_text.split("(")[1].split(")")[0].strip()
            else:
                content = "Not anonymous"
        else:
            content = "Not anonymous"
        return {"link": f"https://spur.us/context/{ip}", "tunnels": content}
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None
