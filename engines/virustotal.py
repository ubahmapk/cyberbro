import base64
import logging
from typing import Any

import requests

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

NAME: str = "virustotal"
LABEL: str = "VirusTotal"
SUPPORTS: list[str] = ["hash", "risk", "IP", "domain", "URL"]
DESCRIPTION: str = "Checks VirusTotal for IP, domain, URL, hash, free API key required"
COST: str = "Free"
API_KEY_REQUIRED: bool = True
MIGRATED: bool = False


def map_observable_type_to_url(observable: str, observable_type: str) -> tuple[str, str]:
    """
    Determine the correct endpoint & link based on the observable type

    Args:
        obsservable (str)
        observable_type (str)

    Returns:
        str: The corresponding VT URL
    """

    match observable_type:
        case "IPv4" | "IPv6":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable}"
            link = f"https://www.virustotal.com/gui/ip-address/{observable}/detection"
        case "FQDN":
            url = f"https://www.virustotal.com/api/v3/domains/{observable}"
            link = f"https://www.virustotal.com/gui/domain/{observable}/detection"
        case "URL":
            encoded_url = base64.urlsafe_b64encode(observable.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
            link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
        case _:
            # Assume a file hash
            url = f"https://www.virustotal.com/api/v3/files/{observable}"
            link = f"https://www.virustotal.com/gui/file/{observable}/detection"

    return url, link


def run_engine(
    observable_dict: dict,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Queries the VirusTotal API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        observable_type (str): The type of the observable ("IPv4", "FQDN", "URL", "MD5", etc.).
        api_key (str): VirusTotal API key.
        proxies (dict): Dictionary of proxies.

    Returns:
        dict: Contains detection ratio, total malicious, link, and community_score, for example:
            {
                "detection_ratio": "5/70",
                "total_malicious": 5,
                "link": "https://www.virustotal.com/gui/ip-address/<ip>/detection",
                "community_score": 10
            }
        None: If any error occurs.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.virustotal

    if not api_key:
        logger.error("VirusTotal API key is not set in the configuration.")
        return None

    observable: str = observable_dict["value"]
    observable_type: str = observable_dict["type"]

    headers: dict[str, str] = {"x-apikey": api_key}
    url, link = map_observable_type_to_url(observable, observable_type)

    try:
        response: requests.Response = requests.get(url, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as req_err:
        logger.error("Network error while querying VirusTotal for '%s': %s", observable, req_err, exc_info=True)
        return None

    try:
        attributes: dict = data["data"]["attributes"]
        stats: dict = attributes.get("last_analysis_stats", {})

        total_malicious: int = stats.get("malicious", 0)
        total_engines: int = sum(stats.values()) if stats else 0
        detection_ratio: str = f"{total_malicious}/{total_engines}" if total_engines else "0/0"

        # 'reputation' is usually the community score
        community_score: str = attributes.get("reputation", "Unknown")

        return {
            "detection_ratio": detection_ratio,
            "total_malicious": total_malicious,
            "link": link,
            "community_score": community_score,
        }
    except KeyError:
        # If 'data' or 'attributes' key is missing, fallback
        logger.warning("VirusTotal response missing expected keys for '%s': %s", observable, data)
        return {
            "detection_ratio": "0/0",
            "total_malicious": 0,
            "link": f"https://www.virustotal.com/gui/search/{observable}",
            "community_score": 0,
        }

    return None
