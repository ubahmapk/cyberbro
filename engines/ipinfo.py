import logging
from typing import Any, Optional

import pycountry
import requests

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

NAME: str = "ipinfo"
LABEL: str = "IPInfo"
SUPPORTS: list[str] = ["IP"]
DESCRIPTION: str = "Checks IPinfo for IP, reversed obtained IP for a given domain/URL, free API key required."
COST: str = "Free"
API_KEY_REQUIRED: bool = True
MIGRATED: bool = False


def run_engine(
    observable_dict: dict, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, Any] | None:
    """
    Queries the IP information from the ipinfo.io API.

    Args:
        ip (str): The IP address to query.
        api_key (str): The API key for ipinfo.io.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing extracted information:
            {
                "ip": ...,
                "geolocation": "city, region",
                "country_code": ...,
                "country_name": ...,
                "hostname": ...,
                "asn": ...,
                "link": "https://ipinfo.io/..."
            }
        None: If an error occurs or 'ip' key isn't in the response.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.ipinfo
    if not api_key:
        logger.error("API key for IPInfo is required but not provided.")
        return None

    ip: str = observable_dict["value"]

    url = f"https://ipinfo.io/{ip}/json?token={api_key}"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error("Error querying ipinfo for '%s': %s", ip, e, exc_info=True)
        return None

    if "bogon" in data:
        return {
            "ip": ip,
            "geolocation": "",
            "country_code": "",
            "country_name": "",
            "hostname": "Private IP",
            "asn": "BOGON",
            "link": f"https://ipinfo.io/{ip}",
        }

    if "ip" not in data:
        return None

    ip_resp = data.get("ip", "Unknown")
    hostname = data.get("hostname", "Unknown")
    city = data.get("city", "Unknown")
    region = data.get("region", "Unknown")
    asn = data.get("org", "Unknown")
    country_code = data.get("country", "Unknown")

    # Attempt to resolve country name
    try:
        country_obj = pycountry.countries.get(alpha_2=country_code)
        country_name: str = country_obj.name if country_obj else "Unknown"
    except Exception:
        country_name = "Unknown"

    return {
        "ip": ip_resp,
        "geolocation": f"{city}, {region}",
        "country_code": country_code,
        "country_name": country_name,
        "hostname": hostname,
        "asn": asn,
        "link": f"https://ipinfo.io/{ip_resp}",
    }
