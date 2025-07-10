import logging
from typing import Any

import requests

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "URL",
]

NAME: str = "google_safe_browsing"
LABEL: str = "Google Safe Browsing"
SUPPORTS: list[str] = ["IP", "domain", "risk"]
DESCRIPTION: str = "Checks Google Safe Browsing API to check if the given observable is associated with any threats."
COST: str = "Free"
API_KEY_REQUIRED: bool = True


def run_engine(
    observable_dict: dict,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Queries the Google Safe Browsing API to check if the given observable is associated with any threats.

    Args:
        observable (str): The observable to be checked (URL, FQDN, or IP).
        observable_type (str): The type of the observable (e.g., "URL", "FQDN", "IPv4", "IPv6").
        api_key (str): Your Google Safe Browsing API key.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing the result of the query with the structure:
            {
                "threat_found": "Threat found" or "No threat found",
                "details": [...] or None
            }
        None: If an error occurs or the API request fails.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.google_safe_browsing

    return_result: dict | None = None

    if not api_key:
        logger.error("Google Safe Browsing API key is required but not provided.")
        return None

    observable: str = observable_dict["value"]
    observable_type: str = observable_dict["type"]

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    threat_entries: list[dict] = []
    # Assign the URL to check based on the observable type
    if observable_type == "URL":
        threat_entries.append({"url": observable})
    elif observable_type == "FQDN" or observable_type in ["IPv4", "IPv6"]:
        threat_entries.append({"url": f"http://{observable}"})
    else:
        logger.warning(
            "Unsupported observable_type '%s' for Google Safe Browsing.",
            observable_type,
        )
        return None

    body = {
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ALL"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries,
        }
    }

    try:
        response = requests.post(url, json=body, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "matches" in data:
            return {"threat_found": "Threat found", "details": data["matches"]}
        return_result = {"threat_found": "No threat found", "details": None}

    except requests.exceptions.RequestException as e:
        logger.error(
            "Error while querying Google Safe Browsing for '%s': %s",
            observable,
            e,
            exc_info=True,
        )

    return return_result
