import json
import logging
from typing import Any, Optional

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


def query_dfir_iris(
    observable: str,
    dfir_iris_api_key: str,
    dfir_iris_url: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the DFIR_IRIS API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        dfir_iris_api_key (str): DFIR_IRIS API key.
        dfir_iris_url (str): DFIR_IRIS url.
        proxies (dict): Dictionary of proxies.
        ssl_verify (bool): Verify certificate.

    Returns:
        dict: A dictionary with number of cases with the indicator, and the case id links, for example:
            {
                "reports": 3,
                "links": ["https://dfir_iris_url/case/ioc?cid=3","https://dfir_iris_url/case/ioc?cid=4"]
            }
        None: If any error occurs.
    """
    url = f"{dfir_iris_url}/search?cid=1"
    try:
        headers = {"Authorization": f"Bearer {dfir_iris_api_key}", "Content-Type": "application/json"}
        body = {"search_value": f"{observable}", "search_type": "ioc"}
        payload = json.dumps(body)
        response = requests.post(url, headers=headers, data=payload, proxies=None, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "data" not in data:
            logger.warning("DFIR_IRIS response has no 'data' key. Full response: %s", data)
            return None

        if len(data["data"]) > 0:
            reports = len(data["data"])
            links = []
            for i in data["data"]:
                case_id = i["case_id"]
                link = f"{dfir_iris_url}/case/ioc?cid={case_id}"
                links.append(link)

            return {"reports": reports, "links": links}

        return None

    except Exception as e:
        logger.error("Error querying DFIR-IRIS for '%s': %s", observable, e, exc_info=True)

    return None
