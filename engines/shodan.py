import requests

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

def query_shodan(observable, API_KEY, PROXIES):
    """
    Queries the Shodan API for information about a given observable.

    Args:
        observable (str): The observable (e.g., IP address) to query in Shodan.

    Returns:
        dict: A dictionary containing the Shodan data for the observable, including a link to the Shodan host page.
        None: If the request was unsuccessful or an exception occurred.

    Raises:
        Exception: If an error occurs during the request.
    """
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
            return {"ports": data["ports"], "tags": data["tags"],"link": data["link"]}
        else:
            return None
    except Exception as e:
        print(e)
        return None