import logging
from typing import Any, Optional

import requests
from bs4 import BeautifulSoup

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

NAME: str = "ioc_one_pdf"
LABEL: str = "IOC One (PDF)"
SUPPORTS: list[str] = ["domain", "URL", "IP", "hash", "scraping"]
DESCRIPTION: str = "Scraps (can be long) Ioc.One PDF search results for all types of observable, free, no API key"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(observablei_dict: dict, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Perform a deep search query on ioc.one (PDF).

    Args:
        observable (str): The search query.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary with keys "results" (list of dict) and "link" (str).
        None: If any error occurs.
    """

    observable: str = observablei_dict["value"]
    url = f"https://ioc.one/auth/deep_search/pdf?search={observable}"

    try:
        response = requests.get(
            url,
            proxies=proxies,
            verify=ssl_verify,
            headers={"User-Agent": "cyberbro"},
            timeout=5,
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        cards = soup.find_all("div", class_="card box-shadow my-1")

        search_results = []
        for card in cards[:5]:
            header = card.find("div", class_="card-header").get_text(strip=True)
            title = card.find("h5", class_="card-title").get_text(strip=True)
            source = card.find("a", class_="btn border btn-primary mx-1", target="_blank")["href"]
            search_results.append({"header": header, "title": title, "source": source})

        return {"results": search_results, "link": url}

    except Exception as e:
        logger.error("Error querying ioc.one (PDF) for '%s': %s", observable, e, exc_info=True)

    return None
