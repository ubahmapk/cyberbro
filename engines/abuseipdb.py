import logging

import requests

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

NAME: str = "abuseipdb"
LABEL: str = "AbuseIPDB"
SUPPORTS: list[str] = ["risk", "IP"]
DESCRIPTION: str = "Checks AbuseIPDB for IP, reversed obtained IP for a given domain / URL"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(ip: str, proxies: dict[str, str] | None, ssl_verify: bool = True) -> dict | None:
    """
    Queries the AbuseIPDB API for information about a given IP address.

    Args:
        ip (str): The IP address to check.
        api_key (str): Your AbuseIPDB API key.
        proxies (Optional[dict]): Dictionary of proxies if needed, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing:
            - "reports" (int): The total number of reports for the IP address.
            - "risk_score" (int): The abuse confidence score for the IP address.
            - "link" (str): A URL to the AbuseIPDB page for the IP address.
        None: If any error occurs or the response is missing necessary data.

    Raises:
        requests.exceptions.RequestException: If there is an issue with the network request.
        ValueError: If the response cannot be parsed as JSON.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.abuseipdb

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip}

    try:
        response: requests.Response = requests.get(
            url,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()  # Raises an HTTPError for 4xx/5xx statuses

        json_response = response.json()
        if "data" not in json_response:
            logger.warning("AbuseIPDB response has no 'data' key. Full response: %s", json_response)
            return None

        data = json_response["data"]
        reports = data.get("totalReports", 0)
        risk_score = data.get("abuseConfidenceScore", 0)
        link = f"https://www.abuseipdb.com/check/{ip}"

        return {"reports": reports, "risk_score": risk_score, "link": link}

    except requests.exceptions.RequestException as req_err:
        logger.error("Network error while querying AbuseIPDB: %s", req_err, exc_info=True)
    except Exception as e:
        logger.error("Unexpected error while querying AbuseIPDB: %s", e, exc_info=True)

    return None
