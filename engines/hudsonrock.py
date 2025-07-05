import logging
from typing import Any
from urllib.parse import ParseResult, urlparse

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "Email",
    "FQDN",
    "URL",
]

NAME: str = "hudsonrock"
LABEL: str = "Hudson Rock"
SUPPORTS: list[str] = ["domain", "URL", "email", "free_no_key"]
DESCRIPTION: str = "Searches Hudson Rocks results for domains, URL, Email, free, no API key"
COST: str = "Free"
API_KEY_REQUIRED: bool = False

def run_engine(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Perform a search query using Hudson Rock API for email or domain observables.

    Args:
        observable (str): The search query string (e.g., an email or domain).
        observable_type (str): The type of observable ('email' or 'domain').
        proxies (dict): Dictionary containing proxy settings, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing the search results.
        None: If an error occurs (network, parsing, etc.).
    """
    try:
        if observable_type == "URL":
            parsed_url: ParseResult = urlparse(observable)
            observable: str = parsed_url.netloc
            if not observable:
                logger.error(f"Invalid URL provided: {observable}")
                return None
            observable_type = "FQDN"

        match observable_type:
            case "Email":
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={observable}"
            case "FQDN":
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={observable}"
            case _:
                logger.error("Unsupported observable type: %s", observable_type)
                return None

        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(
            "Error while querying Hudson Rock for '%s': %s",
            observable,
            e,
            exc_info=True,
        )
        return None

    try:
        # Remove any URL / domain that contains "••" for reducing output size
        if observable_type == "FQDN":
            for section in ["data", "stats"]:
                if section in data:
                    for key in ["all_urls", "clients_urls", "employees_urls"]:
                        if key in data[section]:
                            data[section][key] = [
                                entry for entry in data[section][key] if "url" not in entry or "••" not in entry["url"]
                            ]
                if section == "stats":
                    for key in ["clients_urls", "employees_urls"]:
                        if key in data[section]:
                            data[section][key] = [url for url in data[section][key] if "••" not in url]
                if "thirdPartyDomains" in data:
                    data["thirdPartyDomains"] = [
                        entry
                        for entry in data["thirdPartyDomains"]
                        if "domain" in entry and entry["domain"] is not None and "••" not in entry["domain"]
                    ]
        return data

    except Exception as e:
        logger.error(
            "Error while querying Hudson Rock for '%s': %s",
            observable,
            e,
            exc_info=True,
        )
    return None
