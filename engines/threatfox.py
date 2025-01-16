import json
import requests

# Disable SSL warning
requests.packages.urllib3.disable_warnings()

def query_threatfox(observable, observable_type, PROXIES):
    """
    Queries the ThreatFox API for information about a given observable.
    Args:
        observable (str): The observable to search for (e.g., URL, IP address, hash).
        observable_type (str): The type of the observable (e.g., "URL", "IP", "hash").
        PROXIES (dict): A dictionary of proxies to use for the request.
    Returns:
        dict: A dictionary containing:
            - "count" (int): The number of results found.
            - "malware_printable" (list): A list of malware printable names associated with the observable.
            - "link" (str): A link to the ThreatFox page with more information about the observable.
    Raises:
        requests.exceptions.RequestException: If the HTTP request fails.
        json.JSONDecodeError: If the response cannot be decoded as JSON.
    """
    
    if observable_type == "URL":
        observable = observable.split("/")[2].split(":")[0]

    url = "https://threatfox-api.abuse.ch/api/v1/"
    
    payload = {"query": "search_ioc", "search_term": observable}

    try:
        response = requests.post(url, data=json.dumps(payload), proxies=PROXIES, verify=False, timeout=5)
        response.raise_for_status()
        result = response.json()

        data = result.get("data", [])
        malware_printable_set = set()

        if data and isinstance(data, list):
            for element in data:
                malware_printable = element.get("malware_printable", "Unknown") if element else None
                malware_printable_set.add(malware_printable)
            count = len(data)
        else:
            count = 0

        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{observable}"

        return {"count": count, "malware_printable": list(malware_printable_set), "link": link}

    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None
