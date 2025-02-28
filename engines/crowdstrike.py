import logging
from falconpy import APIHarnessV2
from typing import Optional, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def map_observable_type(observable_type: str) -> str:
    if observable_type in ["MD5", "SHA256"]:
        return observable_type.lower()
    elif observable_type in ["IPv4", "IPv6"]:
        return observable_type.lower()
    elif observable_type in ["FQDN", "URL"]:
        return "domain"
    
def generate_ioc_id(observable: str, observable_type: str) -> str:
    if observable_type == "domain":
        return f"domain_{observable}"
    elif observable_type in ["ipv4", "ipv6"]:
        return f"ip_address_{observable}"
    elif observable_type == "md5":
        return f"hash_md5_{observable}"
    elif observable_type == "sha256":
        return f"hash_sha256_{observable}"

def get_falcon_client(client_id: str, client_secret: str, proxies: Dict[str, str]) -> APIHarnessV2:
    return APIHarnessV2(client_id=client_id, client_secret=client_secret, proxy=proxies)

def query_crowdstrike(observable: str, observable_type: str, client_id: str, client_secret: str, proxies: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Queries CrowdStrike Falcon for information about a given observable.

    Args:
        observable (str): The observable to query.
        observable_type (str): The type of the observable (e.g., 'URL', 'MD5', 'SHA256'). Note: SHA1 are not supported (official doc).
        client_id (str): The client ID for CrowdStrike API authentication.
        client_secret (str): The client secret for CrowdStrike API authentication.
        proxies (Dict[str, str]): Proxy settings for the API client.

    Returns:
        Optional[Dict[str, Any]]: A dictionary with the query results or None if an error occurs.
    """
    falcon = get_falcon_client(client_id, client_secret, proxies)

    try:
        if observable_type == "URL":
            observable = observable.split("/")[2].split(":")[0]

        observable = observable.lower()
        observable_type = map_observable_type(observable_type)

        response = falcon.command("indicator_get_device_count_v1", type=observable_type, value=observable)
        logger.debug("Falcon response: %s", response)

        if response['status_code'] != 200:
            logger.debug("Indicator not found: %s", response['body']['errors'][0]['message'])
            result = {"device_count": 0}
        else:
            data = response['body']['resources'][0]
            result = {"device_count": data.get('device_count', 0)}

        id_to_search = generate_ioc_id(observable, observable_type)
        BODY = {"ids": [id_to_search]}

        response = falcon.command("GetIntelIndicatorEntities", body=BODY)
        logger.debug("GetIntelIndicatorEntities response: %s", response)

        if response['status_code'] != 200 or not response['body']['resources']:
            logger.debug("Indicator not found or error in response: %s", response)
            result.update({
                "indicator_found": False,
                "published_date": "",
                "last_updated": "",
                "actors": [],
                "malicious_confidence": "",
                "threat_types": [],
                "kill_chain": [],
                "malware_families": [],
                "vulnerabilities": [],
                "link": f"https://falcon.crowdstrike.com/search/?term=_all%3A~%27{observable}%27"
            })
            return result

        resource = response['body']['resources'][0]
        result.update({
            "indicator_found": True,
            "published_date": datetime.fromtimestamp(resource.get('published_date', 0), tz=timezone.utc).strftime('%Y-%m-%d'),
            "last_updated": datetime.fromtimestamp(resource.get('last_updated', 0), tz=timezone.utc).strftime('%Y-%m-%d'),
            "actors": resource.get('actors', []),
            "malicious_confidence": resource.get('malicious_confidence', ''),
            "threat_types": resource.get('threat_types', []),
            "kill_chain": resource.get('kill_chains', []),
            "malware_families": resource.get('malware_families', []),
            "vulnerabilities": resource.get('vulnerabilities', []),
            "link": f"https://falcon.crowdstrike.com/search/?term=_all%3A~%27{observable}%27"
        })

        return result

    except Exception as e:
        logger.error("Error querying CrowdStrike Falcon for '%s': %s", observable, e, exc_info=True)
        return None