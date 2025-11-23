import logging
from collections import Counter

import requests
from pydantic import ValidationError
from requests.exceptions import JSONDecodeError, RequestException

from models.crtsh_datamodel import Certificate
from models.datatypes import ObservableMap, Proxies, Report
from utils.config import QueryError

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "URL",
]

NAME: str = "crtsh"
LABEL: str = "crt.sh"
SUPPORTS: list[str] = ["domain", "IP"]
DESCRIPTION: str = "Queries the crt.sh API for information about a given observable (URL or FQDN)."
COST: str = "Free"
API_KEY_REQUIRED: bool = False
MIGRATED: bool = True


def run_engine(
    observable_dict: ObservableMap,
    proxies: Proxies,
    ssl_verify: bool,
) -> Report | None:
    """
    Queries the crt.sh API for information about a given observable (URL or FQDN).

    Args:
        observable (ObservableMap): The observable mapping, including the value and type
        proxies (Proxies): The proxy servers to use for the request.
        ssl_verify (bool): TLS verification setting

    Returns:
        (Report | None) : A dictionary containing "scan_count", "top_domains", and "link", or None
            if an error occurs.
            For example:
            {
                "top_domains": [{"domain": "example.com", "count": 5}, ...],
                "link": "https://crt.sh/?q=example.com"
            }
    """

    target: str = observable_dict["value"]

    # If observable is a URL, extract domain
    if (observable_dict["type"]) == "URL":
        domain_part = target.split("/")[2].split(":")[0]
        target = domain_part

    try:
        query_results: list[dict] = query_engine(target, proxies, ssl_verify)
        report: Report = parse_results(query_results, target)
    except QueryError as e:
        logger.error(e)
        return None

    return report


def query_engine(target: str, proxies: Proxies, ssl_verify: bool = True) -> list[dict]:
    url = f"https://crt.sh/json?q={target}"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=20)
        response.raise_for_status()

        results = response.json()
    except (RequestException, JSONDecodeError) as e:
        logger.error(f"Error querying crt.sh for {target}: {e}", exc_info=True)
        raise QueryError from e

    if len(results) < 1:
        raise QueryError(f"No results for {target}")

    return results


def parse_results(query_results: list[dict], target: str) -> Report:
    """Parse dict into a list of Certificate objects"""
    results: list[Certificate] = []

    for certificate in query_results:
        try:
            results.append(Certificate(**certificate))
        except ValidationError:
            continue

    domain_count: Counter = Counter()
    for certificate in results:
        domains = set()

        if certificate.common_name:
            domains.add(certificate.common_name)

        if certificate.name_value:
            for el in certificate.name_value.split("\n"):
                if len(el) > 0:
                    domains.add(str(el).strip())

        for domain in domains:
            domain_count[domain] += 1

    # Sort and extract top 5
    sorted_domains: list[tuple[str, int]] = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
    top_domains: list[dict[str, str | int]] = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]
    return Report(
        {
            "top_domains": top_domains,
            "link": f"https://crt.sh/?q={target}",
        }
    )
