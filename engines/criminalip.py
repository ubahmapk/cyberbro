import json
import logging

import requests
from pydantic import ValidationError
from requests.exceptions import RequestException

from models.criminalip_datamodel import SuspiciousInfoReport
from utils.config import APIKeyNotFoundError, QueryError, read_api_key

"""
Criminal IP API integration for retrieving suspicious information about IP addresses.

API info for Suspicious Info Report aavailable at https://www.criminalip.io/developer/api/get-v2-ip-suspicious-info
"""

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]
NAME: str = "criminalip"
LABEL: str = "Criminal IP"
SUPPORTS: list[str] = ["IP", "risk", "VPN", "proxy"]
DESCRIPTION: str = "Checks CriminalIP for IP, reversed obtained IP for a given domain / URL"
COST: str = "Free, with paid upgrades available"
API_KEY_REQUIRED: bool = True


BASE_URL: str = "https://api.criminalip.io"


def query_criminalip(
    api_key: str,
    ip: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict:
    """Retrieve 'Suspicious Info' Report."""

    url: str = f"{BASE_URL}/v2/feature/ip/suspicious-info"
    params: dict = {"ip": ip}
    headers: dict = {"x-api-key": f"{api_key}"}

    try:
        response = requests.get(url, params=params, headers=headers, proxies=proxies, verify=ssl_verify)
        response.raise_for_status()
        query_result: dict = response.json()
    except RequestException as e:
        logger.error(f"Error retrieving Criminal IP Suspicious Info report for {ip}: {e}")
        raise QueryError from e

    return query_result


def parse_criminalip_response(response: dict) -> SuspiciousInfoReport:
    try:
        suspcious_info_report: SuspiciousInfoReport = SuspiciousInfoReport(**response)
    except ValidationError as e:
        logger.error(f"Error validating Criminal IP Suspicious Info report for {ip}: {e}")
        raise QueryError from e

    return suspcious_info_report


def run_engine(observable_dict: dict, proxies: dict[str, str] | None = None, ssl_verify: bool = True) -> dict | None:
    """Perform Criminal IP analysis."""

    try:
        api_key: str = read_api_key("criminalip")
    except APIKeyNotFoundError:
        logger.error("API key for CriminalIP engine is not configured.")
        return None

    ip: str = observable_dict["value"]

    try:
        query_response: dict = query_criminalip(api_key, ip, proxies, ssl_verify)
        response: SuspiciousInfoReport = parse_criminalip_response(query_response)
    except QueryError:
        logger.error(f"Failed to retrieve suspicious info report for IP: {ip}")
        return None

    return json.loads(response.model_dump_json())


if __name__ == "__main__":
    # Example usage

    try:
        api_key: str = read_api_key("criminalip")
    except APIKeyNotFoundError:
        logger.error("API key is not configured.")
        exit(1)

    ssl_verify: bool = False

    ip: str = input("Enter an IP address: ")

    if not ip:
        logger.error("No observable provided.")
        exit(1)

    report: SuspiciousInfoReport | None = query_criminalip(api_key, ip, ssl_verify=ssl_verify)

    if report:
        print("Suspicious Info Report:")
        print(report)
    else:
        logger.error("Failed to retrieve the report.")
