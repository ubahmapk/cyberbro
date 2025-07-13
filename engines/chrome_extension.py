import logging

import requests
from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import ConnectionError, RequestException

from models.datatypes import ObservableMap, Proxies, Report
from utils.config import QueryError

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "CHROME_EXTENSION",
]

NAME: str = "chrome_extension"
LABEL: str = "Chrome Extension"
SUPPORTS: list[str] = ["hash"]
DESCRIPTION: str = "Fetch the name of a Chrome or Edge extension using its ID"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(observable: ObservableMap, proxies: Proxies, ssl_verify: bool = True) -> Report | None:
    """
    Fetch the name of a Chrome or Edge extension using its ID.

    Args:
        observable (dict[str, str]): The observable mapping, including the value and type
        proxies (dict[str, str]): The proxy servers to use for the request.
        ssl_verify (bool): TLS verification setting

    Returns:
        result (dict[str, str] | None): A dictionary containing the name and URL of the extension, or None if not found.

    Raises:
        QueryError: If the request fails or the extension name is not found.
    """
    extension_id: str = observable["value"]

    chrome_url = f"https://chromewebstore.google.com/detail/{extension_id}"
    edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{extension_id}"

    for url in [chrome_url, edge_url]:
        try:
            resp = fetch_extension_page(url, proxies, ssl_verify)
            result = parse_extension_name(resp, url)
            if result["name"]:
                return result
        except KeyError:
            continue
        except QueryError:
            logger.error("Unable to find browser extension with that ID")
            continue

    return None


def fetch_extension_page(url: str, proxies: Proxies, ssl_verify: bool = True) -> Response:
    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
    except (RequestException, ConnectionError) as e:
        logger.error(f"Error retrieving extension page: {e=}")
        raise QueryError from None

    return response


def parse_extension_name(response: Response, url: str) -> Report:
    """
    Parse the Response object for an extension name.

    Args:
        response (requests.Response): A Response object containg the HTML response from a request
        url (str): The URL that was used in the request (used to determine which browser the extension if for)

    Returns:
        result (dict[str, str]): A dictionary containing the name and URL of the extension

    Raises:
        QueryError: If no extension is found or if the BeautifulSoup parsing fails
    """

    try:
        soup = BeautifulSoup(response.content, "html.parser")
    except Exception as e:
        logger.error(f"Error parsing HTML response: {e=}")
        raise QueryError from e

    if response.request and ("micosoftedge.microsoft.com" in url):
        title_tag = soup.find("title")
        if title_tag:
            return Report({"name": title_tag.text.strip().split("-")[0].strip(), "url": url})
    if "chromewebstore.google.com" in url:
        h1_tag = soup.find("h1")
        if h1_tag:
            return Report({"name": h1_tag.text.strip(), "url": url})

    logger.info(f"No extension found with Id {response.request.path_url.split(sep='/')[-1].strip()}")
    raise QueryError
