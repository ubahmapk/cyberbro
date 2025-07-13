import logging

import requests

from models.datatypes import ObservableMap, Proxies, Report

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
        response = requests.get(
            f"https://grep.app/api/search?q={observable}",
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()

        if data["hits"]["total"] == 0:
            return {"results": []}

        search_results = []
        seen_repos = set()
        for hit in data["hits"]["hits"]:
            repo_name = hit["repo"]["raw"]
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

        return {"results": search_results}

    except Exception as e:
        logger.error("Error while querying GitHub for '%s': %s", observable, e, exc_info=True)

        return None
