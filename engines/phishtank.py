import base64
import requests
from urllib.parse import urlparse

# Disable SSL warning in case of proxies that break SSL
requests.packages.urllib3.disable_warnings()

def query_phishtank(observable, observable_type, PROXIES):
    """
    Query the PhishTank API to check if a given observable is a known phishing URL.
    Uses the user-agent "phishtank/IntelOwl" for the request since IntelOwl is allowed by PhishTank.

    Check IntelOwl project on GitHub: https://github.com/intelowlproject/IntelOwl

    Args:
        observable (str): The observable to be checked (e.g., URL or FQDN).
        observable_type (str): The type of the observable (e.g., "URL" or "FQDN").
        PROXIES (dict): A dictionary of proxies to be used for the request.

    Returns:
        dict: The results from the PhishTank API if the request is successful.
        None: If there is an exception during the request.
    """
    headers = {"User-Agent": "phishtank/IntelOwl"}
    observable_to_analyze = observable
    if observable_type == "FQDN":
        observable_to_analyze = "http://" + observable
    parsed = urlparse(observable_to_analyze)
    if not parsed.path:
        observable_to_analyze += "/"
    data = {
        "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
        "format": "json",
    }
    try:
        response = requests.post("https://checkurl.phishtank.com/checkurl/", data=data, headers=headers, proxies=PROXIES, verify=False)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        data = response.json()
        print(data["results"])
        return data["results"]
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except ValueError as e:
        print(f"Error parsing JSON response: {e}")
    except KeyError as e:
        print(f"Expected key not found in response: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return None