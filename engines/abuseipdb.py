import logging
from typing import Any

import requests
from requests.exceptions import JSONDecodeError, RequestException

from models.datatypes import ObservableMap, Proxies, Report
from utils.config import APIKeyNotFoundError, QueryError, read_api_key

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = ["IPv4", "IPv6"]

NAME: str = "abuseipdb"
LABEL: str = "AbuseIPDB"
SUPPORTS: list[str] = ["risk", "IP"]
DESCRIPTION: str = "Checks AbuseIPDB for IP, reversed obtained IP for a given domain / URL"
COST: str = "Free"
API_KEY_REQUIRED: bool = False
MIGRATED: bool = True


def run_engine(observable: ObservableMap, proxies: Proxies, ssl_verify: bool = True) -> Report | None:
    """
    Entrypoint for the AbuseIPDB engine.

    Retrieves API key and queries the AbuseIPDB API for information about the given observable.

    Return
    """

    try:
        api_key: str = read_api_key(NAME)
    except APIKeyNotFoundError as e:
        logger.error(f"{LABEL} API key is not configured: %s", e)
        return None

    ip: str = observable["value"]

    try:
        response: dict = query_abuseipdb(
            ip=ip,
            api_key=api_key,
            proxies=proxies,
            ssl_verify=ssl_verify,
        )
        report: Report = parse_abuseipdb_response(response, ip)
    except QueryError as e:
        logger.error("Error querying AbuseIPDB: %s", e, exc_info=True)
        return None

    return report


def query_abuseipdb(ip: str, api_key: str, proxies: Proxies, ssl_verify: bool = True) -> dict[str, Any]:
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
        RequestException: If there is an issue with the network request.
        ValueError: If the response cannot be parsed as JSON.
    """

    url: str = "https://api.abuseipdb.com/api/v2/check"
    headers: dict[str, str] = {"Key": api_key, "Accept": "application/json"}
    params: dict[str, str] = {"ipAddress": ip}

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
    except (JSONDecodeError, RequestException) as req_err:
        logger.error("Network error while querying AbuseIPDB: %s", req_err, exc_info=True)
        raise QueryError from req_err

    return json_response


def parse_abuseipdb_response(json_response: dict, ip: str) -> Report:
    try:
        data: dict[str, Any] = json_response["data"]
        reports: int = data.get("totalReports", 0)
        risk_score: int = data.get("abuseConfidenceScore", 0)
        link = f"https://www.abuseipdb.com/check/{ip}"
    except (KeyError, TypeError) as e:
        logger.warning("AbuseIPDB response has no 'data' key. Full response: %s", json_response)
        raise QueryError("Invalid response format from AbuseIPDB") from e

    return Report({"reports": reports, "risk_score": risk_score, "link": link})
