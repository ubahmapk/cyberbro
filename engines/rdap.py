import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_openrdap(observable, observable_type, PROXIES):
    """
    Queries the Open RDAP service for information about a given domain.
    Open RDAP is a free RDAP resolver that provides information about domain names.

    Parameters:
    observable (str): The observable to query (e.g., URL or FQDN).
    observable_type (str): The type of the observable ("URL" or "FQDN").
    PROXIES (dict): A dictionary of proxies to use for the request.

    Returns:
    dict: The JSON response from the RDAP service, or None if an error occurs.
    """
    try:
        if observable_type == "URL":
            domain = observable.split("/")[2].split(":")[0]
        elif observable_type == "FQDN":
            domain = observable
        else:
            return None

        api_url = f"https://rdap.net/domain/{domain}"
        response = requests.get(api_url, verify=False, proxies=PROXIES)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        
        data = response.json()
        
        abuse_contact = "Unknown"
        registrar = "Unknown"
        name_servers = []
        creation_date = "Unknown"
        expiration_date = "Unknown"
        update_date = "Unknown"
        link = "Unknown"

        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            if 'abuse' in roles:
                for vcard in entity.get('vcardArray', [])[1]:
                    if vcard[0] == 'email' and vcard[3] != '':
                        abuse_contact = vcard[3]
            if 'registrar' in roles:
                for vcard in entity.get('vcardArray', [])[1]:
                    if vcard[0] == 'fn':
                        registrar = vcard[3]
            for sub_entity in entity.get('entities', []):
                if 'abuse' in sub_entity.get('roles', []):
                    for vcard in sub_entity.get('vcardArray', [])[1]:
                        if vcard[0] == 'email':
                            abuse_contact = vcard[3]
        
        for ns in data.get('nameservers', []):
            name_servers.append(ns.get('ldhName').lower())

        for event in data.get('events', []):
            if event.get('eventAction') == 'registration':
                creation_date = event.get('eventDate').split("T")[0]
            if event.get('eventAction') == 'expiration':
                expiration_date = event.get('eventDate').split("T")[0]
            if event.get('eventAction') == 'last changed':
                update_date = event.get('eventDate').split("T")[0]

        for el in data.get('links', []):
            if el.get('rel') == 'self':
                link = el.get('href')

        return {
            'abuse_contact': abuse_contact,
            'registrar': registrar,
            'name_servers': name_servers,
            'creation_date': creation_date,
            'expiration_date': expiration_date,
            'update_date': update_date,
            'link': link
        }
    except (requests.RequestException, IndexError, ValueError) as e:
        # Log the error if needed
        return None