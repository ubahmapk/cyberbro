import logging
from typing import Any, Optional

from googlesearch import search

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "CHROME_EXTENSION",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

NAME: str = "google"
LABEL: str = "Google"
SUPPORTS: list[str] = ["domain", "URL", "IP", "hash", "scraping", "chrome_extension_id", "edge_extension_id"]
DESCRIPTION: str = "Checks Google search results for all types of observable"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(
    observable_dict: dict, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> Optional[dict[str, Any]]:
    """
    Perform a Google search query limited to 5 search results.

    Args:
        observable (str): The search query.
        proxies (dict): Dictionary containing proxy settings, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing the search results under the key "results":
            {
                "results": [
                    {"title": ..., "description": ..., "url": ...},
                    ...
                ]
            }
        None: If an error occurs (network, parsing, etc.).
    """

    observable: str = observable_dict["value"]

    try:
        search_iterator = search(
            f'"{observable}"',
            num_results=5,
            proxy=proxies.get("http", None) if proxies else None,
            ssl_verify=ssl_verify,
            advanced=True,
            lang="en",
            region="US",
        )

        search_results = []
        for result in search_iterator:
            search_results.append(
                {
                    "title": result.title,
                    "description": result.description,
                    "url": result.url,
                }
            )

        return {"results": search_results}

    except Exception as e:
        logger.error("Error while querying Google for '%s': %s", observable, e, exc_info=True)

    return None
