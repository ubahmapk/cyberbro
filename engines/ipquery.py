import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

NAME: str = "ipquery"
LABEL: str = "IPQuery"
SUPPORTS: list[str] = ["default", "IP", "risk", "VPN", "proxy", "free_no_key"]
DESCRIPTION: str = "Checks IPquery for IP, reversed obtained IP for a given domain/URL, free, no API key"
COST: str = "Free"
API_KEY_REQUIRED: bool = False
MIGRATED: bool = False


def run_engine(
    observable_dict: dict, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, Any] | None:
    """
    Queries the IP information from the ipquery.io API.

    Args:
        ip (str): The IP address to query.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing extracted information:
            {
                "ip": ...,
                "geolocation": "city, region",
                "country_code": ...,
                "country_name": ...,
                "isp": ...,
                "asn": ...,
                "is_vpn": ...,
                "is_tor": ...,
                "is_proxy": ...,
                "risk_score": ...,
                "link": ...
            }
        None: If an error occurs or 'ip' key isn't in the response.
    """

    ip: str = observable_dict["value"]
    url = f"https://api.ipquery.io/{ip}"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error("Error querying ipquery for '%s': %s", ip, e, exc_info=True)
        return None

    if "ip" not in data:
        return None

    ip_resp = data.get("ip", "Unknown")
    city = data.get("location", {}).get("city", "Unknown")
    region = data.get("location", {}).get("state", "Unknown")
    country_code = data.get("location", {}).get("country_code", "Unknown")
    country_name = data.get("location", {}).get("country", "Unknown")
    isp = data.get("isp", {}).get("isp", "Unknown")
    asn = data.get("isp", {}).get("asn", "Unknown")

    is_vpn = data.get("risk", {}).get("is_vpn", False)
    is_tor = data.get("risk", {}).get("is_tor", False)
    is_proxy = data.get("risk", {}).get("is_proxy", False)
    risk_score = data.get("risk", {}).get("risk_score", "Unknown")

    return {
        "ip": ip_resp,
        "geolocation": f"{city}, {region}",
        "country_code": country_code,
        "country_name": country_name,
        "isp": isp,
        "asn": asn,
        "is_vpn": is_vpn,
        "is_tor": is_tor,
        "is_proxy": is_proxy,
        "risk_score": risk_score,
        "link": f"https://api.ipquery.io/{ip_resp}",
    }
