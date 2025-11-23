import logging
from typing import Any

import requests

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

NAME: str = "urlscan"
LABEL: str = "URLScan"
SUPPORTS: list[str] = ["hash", "domain", "IP"]
DESCRIPTION: str = "Queries the urlscan.io API for information about a given observable (URL, IP, or file hash)"
COST: str = "Free"
API_KEY_REQUIRED: bool = False
MIGRATED: bool = False


def run_engine(
    observable_dict: dict,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Queries the urlscan.io API for information about a given observable (URL, IP, or file hash).

    Args:
        observable (str): The observable to query.
        observable_type (str): The type of the observable (e.g., "URL", "IP", "MD5", "SHA256", etc.).
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary containing "scan_count", "top_domains", and "link". For example:
              {
                  "scan_count": 10,
                  "top_domains": [{"domain": "example.com", "count": 5}, ...],
                  "link": "https://urlscan.io/search/#page.domain:example.com"
              }
        None: If an error occurs.
    """

    observable: str = observable_dict["value"]
    observable_type: str = observable_dict["type"]

    query_fields: dict[str, str] = {
        "IPv4": "ip",
        "IPv6": "ip",
        "MD5": "files.md5",
        "SHA1": "files.sha1",
        "SHA256": "files.sha256",
        "URL": "page.domain",
        "FQDN": "page.domain",
    }
    query_field = query_fields.get(observable_type, "page.domain")

    # If observable is a URL, extract domain
    if observable_type == "URL":
        domain_part = observable.split("/")[2].split(":")[0]
        observable = domain_part

    url = f"https://urlscan.io/api/v1/search/?q={query_field}:{observable}"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        result = response.json()

    except requests.exceptions.RequestException as req_err:
        logger.error(
            "Network error while querying urlscan.io for '%s' (%s): %s",
            observable,
            observable_type,
            req_err,
            exc_info=True,
        )
        return None

    results = result.get("results", [])
    scan_count = result.get("total", 0)

    domain_count = {}
    for entry in results:
        page_info = entry.get("page", {})
        domain = page_info.get("domain", "Unknown")
        domain_count[domain] = domain_count.get(domain, 0) + 1

    # Sort and extract top 5
    sorted_domains = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
    top_domains = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]

    return {
        "scan_count": scan_count,
        "top_domains": top_domains,
        "link": f"https://urlscan.io/search/#{query_field}:{observable}",
    }
