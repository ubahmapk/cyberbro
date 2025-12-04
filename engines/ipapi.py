import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]


def query_ipapi(ip: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Queries the IP information from the ipapi.is API.

    Args:
        ip (str): The IP address to query.
        proxies (dict): Dictionary containing proxy settings.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        dict: The raw API response containing all IP information.
        None: If an error occurs.
    """
    try:
        url = f"https://api.ipapi.is/?q={ip}"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "ip" in data:
            if "asn" in data and "asn" in data["asn"]:
                data["asn"]["asn"] = f"AS{data['asn']['asn']}"
            return data

    except Exception as e:
        logger.error("Error querying ipapi for '%s': %s", ip, e, exc_info=True)

    return None
