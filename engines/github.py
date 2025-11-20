import logging
from typing import Any

import requests
from requests.exceptions import JSONDecodeError, RequestException

from models.datatypes import ObservableMap, Proxies, Report
from utils.config import QueryError

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

NAME: str = "github"
LABEL: str = "Github"
SUPPORTS: list[str] = ["domain", "URL", "IP", "hash", "scraping", "chrome_extension_id", "edge_extension_id"]
DESCRIPTION: str = "Get Github grep.app API search results for all types of observable"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(observable_dict: ObservableMap, proxies: Proxies, ssl_verify: bool = True) -> Report | None:
    """
    Perform a search query using Grep API, limited to 5 search results, restricted to GitHub domains.

    Args:
        observable_dict (ObservableMap): The observable mapping which contains:
        - value (str): The observable to search for (e.g., URL, IP address, domain, hash).
        - type (str): The type of the observable
            (e.g., "URL", "IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5").
        proxies (Proxies): A dictionary of proxies to use for the request.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        (Report | None): A dictionary containing the search results under the key "results",
            or None if there was an error.
            Example:
            {
                "results": [
                    {"title": ..., "url": ...},
                    ...
                ]
            }
    """

    observable: str = observable_dict["value"]

    try:
        query_results: dict[str, Any] = query_engine(observable, proxies, ssl_verify)
        report: Report = parse_results(query_results)
    except QueryError as e:
        logger.error(e)
        return None

    return report


def query_engine(observable: str, proxies: Proxies, ssl_verify: bool = True) -> dict[str, Any]:
    try:
        response = requests.get(
            f"https://grep.app/api/search?q={observable}",
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()

    except (RequestException, JSONDecodeError) as e:
        logger.error("Error while querying GitHub for '%s': %s", observable, e, exc_info=True)
        raise QueryError from e

    return data


def parse_results(data: dict[str, Any]) -> Report:
    try:
        if data["hits"]["total"] == 0:
            return Report({"results": []})
    except KeyError as e:
        logger.error("Unexpected data format from GitHub API: %s", data, exc_info=True)
        raise QueryError(f"Unexpected data format: {e}") from e

    search_results: list[dict[str, str]] = []
    seen_repos: set[str] = set()
    for hit in data["hits"]["hits"]:
        try:
            repo_name = hit["repo"]["raw"]
        except KeyError:
            logger.warning("Missing 'repo' field in hit: %s", hit)
            continue

        if repo_name not in seen_repos:
            seen_repos.add(repo_name)
            search_results.append(
                {
                    "title": repo_name,
                    "url": f"https://github.com/{repo_name}/blob/{hit['branch']['raw']}/{hit['path']['raw']}",
                    "description": hit["path"]["raw"],
                }
            )
        if len(search_results) >= 5:
            break

    return Report(results=search_results)
