import json
import logging
from typing import Any, Optional

import requests

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "URL",
]

NAME: str = "threatfox"
LABEL: str = "ThreatFox"
SUPPORTS: list[str] = ["IP", "domain", "URL"]
DESCRIPTION: str = "Checks ThreatFox by Abuse.ch for IP, domains, URL, free API key required"
COST: str = "Free"
API_KEY_REQUIRED: bool = True

def run_engine(
    observable: str,
    observable_type: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the ThreatFox API for information about a given observable (URL, IP, hash).

    Args:
        observable (str): The observable to search for (e.g., URL, IP address, hash).
        observable_type (str): The type of the observable (e.g., "URL", "IP", "hash").
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary with "count" (int), "malware_printable" (list), and "link" (str). For example:
              {
                  "count": 2,
                  "malware_printable": ["MalwareX", "RansomwareY"],
                  "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A<observable>"
              }
        None: If an error occurs.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.threatfox

    if not api_key:
        logger.error("ThreatFox API key is not set in the configuration.")
        return None

    try:
        # If it's a URL, we typically just want the domain portion for searching
        if observable_type == "URL":
            # e.g., https://example.com/path => domain = example.com
            domain_part = observable.split("/")[2].split(":")[0]
            observable = domain_part

        url: str = "https://threatfox-api.abuse.ch/api/v1/"
        payload: dict[str, str] = {"query": "search_ioc", "search_term": observable}
        headers: dict[str, str] = {"Auth-Key": api_key}

        response: requests.Response = requests.post(
            url,
            data=json.dumps(payload),
            headers=headers,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()

        data = response.json().get("data", [])
        count: int = 0

        malware_printable_set: set[str] = set()
        if isinstance(data, list):
            for item in data:
                if item:
                    malware_name = item.get("malware_printable", "Unknown")
                    malware_printable_set.add(malware_name)

            count = len(data)

        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{observable}"
        return {
            "count": count,
            "malware_printable": list(malware_printable_set),
            "link": link,
        }

    except Exception as e:
        logger.error("Error querying ThreatFox for '%s': %s", observable, e, exc_info=True)

    return None
