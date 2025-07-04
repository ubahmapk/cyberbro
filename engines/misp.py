import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

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

NAME: str = "misp"
LABEL: str = "MISP"
SUPPORTS: list[str] = ["IP", "domain", "URL", "hash"]
DESCRIPTION: str = "Checks MISP for IP, domain, URL, hash, free API key required"
COST: str = "Free"
API_KEY_REQUIRED: bool = True

def map_observable_type(observable_type: str) -> str | list[str]:
    """
    Maps observable type to MISP attribute type.

    Args:
        observable_type (str): The observable type (e.g., "URL", "IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5").

    Returns:
        str: The corresponding MISP attribute type.
        list[str]: A list of MISP attribute types if multiple types are applicable.
    """
    mapping = {
        "URL": "url",
        "IPv4": [
            "ip-dst",
            "ip-src",
            "ip-src|port",
            "ip-dst|port",
            "domain|ip",
        ],
        "IPv6": [
            "ip-dst",
            "ip-src",
            "ip-src|port",
            "ip-dst|port",
            "domain|ip",
        ],
        "FQDN": ["domain", "domain|ip", "hostname", "hostname|port"],
        "SHA256": "sha256",
        "SHA1": "sha1",
        "MD5": "md5",
    }
    return mapping.get(observable_type, "")


def run_engine(
    observable: str,
    observable_type: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Queries the MISP API for information about a given observable (URL, IP, domain, hash).

    Args:
        observable (str): The observable to search for (e.g., URL, IP address, domain, hash).
        observable_type (str): The type of the observable
        (e.g., "URL", "IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5").
        proxies (dict): A dictionary of proxies to use for the request.
        ssl_verify (bool): Whether to verify SSL certificates.
        api_key (str): MISP API key (required).
        misp_url (str): Base URL of the MISP instance.

    Returns:
        dict: A dictionary with "count" (int), "events" (list), "link" (str), "first_seen" (str), and "last_seen" (str).
        None: If an error occurs or API key is missing.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.misp_api_key
    misp_url: str = secrets.misp_url

    if not api_key or not misp_url:
        logger.error("MISP API key and URL are required")
        return None

    try:
        # Ensure the URL is properly formatted
        misp_url = misp_url.rstrip("/")

        # Validate observable type
        if observable_type not in ["IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5", "URL"]:
            logger.error("Unsupported observable type: %s", observable_type)
            return None

        # Prepare the search endpoint
        url = f"{misp_url}/attributes/restSearch"
        headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}

        # map observable type to MISP attribute type
        observable_type: str | list = map_observable_type(observable_type)

        # Prepare the search payload
        payload = {"returnFormat": "json", "value": observable, "type": observable_type}

        # Obviously, a list can be included in the JSON payload just fine, but how does MISP handle it?
        # I don't have access to test this
        response = requests.post(url, json=payload, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        result = response.json()

        attributes = result.get("response", {}).get("Attribute", [])

        event_data = []
        seen_event_ids = set()  # Track unique event IDs
        first_seen = None
        last_seen = None

        count: int = 0

        if isinstance(attributes, list):
            for attribute in attributes:
                # Update first_seen and last_seen and make sure to iterate on all attributes
                timestamp: str = attribute.get("timestamp")
                if timestamp:
                    if first_seen is None or timestamp < first_seen:
                        first_seen = timestamp
                    if last_seen is None or timestamp > last_seen:
                        last_seen = timestamp

                event: dict = attribute.get("Event", {})
                event_id = event.get("id")
                event_title: str = event.get("info", "Unknown")
                event_url: str | None = f"{misp_url}/events/view/{event_id}" if event_id else None

                # Skip if this event ID has already been seen
                if event_id in seen_event_ids:
                    continue

                # Add to seen event IDs and include in output
                seen_event_ids.add(event_id)
                event_data.append({"title": event_title, "url": event_url, "timestamp": timestamp})

                # Sort events by timestamp in descending order (most recent first)
                event_data.sort(key=lambda x: x["timestamp"], reverse=True)

                # Keep only the 5 most recent events to display in Cyberbro
                event_data = event_data[:5]

                # Is this counter supposed to be reset for every attribute?
                count = len(attributes)
        else:
            # Looking at the code flow, if the script reaches here,
            # isn't count still at 0 from above?
            count = 0

        link = f"{misp_url}/attributes/index?value={quote(observable)}"

        # Convert first_seen and last_seen to human-readable format (YYYY-MM-DD)

        if first_seen:
            first_seen = datetime.fromtimestamp(int(first_seen), tz=timezone.utc).strftime("%Y-%m-%d")
        if last_seen:
            last_seen = datetime.fromtimestamp(int(last_seen), tz=timezone.utc).strftime("%Y-%m-%d")

        return {
            "count": count,
            "events": event_data,
            "link": link,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    except Exception as e:
        logger.error("Error querying MISP for '%s': %s", observable, e, exc_info=True)
    return None
