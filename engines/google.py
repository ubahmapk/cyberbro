import logging
import requests
from typing import Optional, Dict, Any
# We assume there's a 'search' function from a library named 'googlesearch'.
from googlesearch import search

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)

def query_google(observable: str, proxies: Dict[str, str]) -> Optional[Dict[str, Any]]:
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
    try:
        search_iterator = search(
            f"\"{observable}\"",
            num_results=5,
            proxy=proxies.get("http"),
            ssl_verify=False,
            advanced=True,
            lang="en",
            region="US"
        )
        
        search_results = []
        for result in search_iterator:
            search_results.append({
                "title": result.title,
                "description": result.description,
                "url": result.url
            })

        return {"results": search_results}

    except Exception as e:
        logger.error("Error while querying Google for '%s': %s", observable, e, exc_info=True)

    return None
