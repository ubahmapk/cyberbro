import json
import logging

import requests
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


class IPQueryError(Exception):
    pass


# Datamodels developed from the IPQuery API documentation at
# https://ipquery.gitbook.io/ipquery-docs#query-specific-ip-address
# as of 9 May 2025


class IPQueryObservable(BaseModel):
    ip: str
    geolocation: str
    country_code: str
    country_name: str
    isp: str
    asn: str
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    risk_score: int
    link: str | None = None


class ISP(BaseModel):
    asn: str = "Unknown"
    org: str = "Unknown"
    isp: str = "Unknown"


class Location(BaseModel):
    country: str = "Unknown"
    country_code: str = "Unknown"
    city: str = "Unknown"
    state: str = "Unknown"
    zipcode: str = "Unknown"
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = "Unknown"
    localtime: str = "Unknown"


class Risk(BaseModel):
    is_mobile: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    risk_score: int = 0


class IPQueryResponse(BaseModel):
    ip: str = "Unknown"
    location: Location
    isp: ISP
    risk: Risk


def query_ipquery(ip: str, proxies: dict[str, str] | None, ssl_verify: bool = True) -> IPQueryResponse:
    """
    Queries the IP information from the ipquery.io API.

    Args:
        ip (str): The IP address to query.
        proxies (dict | None): Dictionary containing proxy settings or None if no proxy is used.
        ssl_verify (bool): Whether to verify SSL certificates. Default is True.

    Returns:
        IPQueryResponse object

    Raises:
        IPQueryError: If there is an error querying the API or validating the response.
    """

    url = f"https://api.ipquery.io/{ip}"
    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error("Error querying ipquery for '%s': %s", ip, e, exc_info=True)
        raise IPQueryError(f"Error retrieving ipquery results for '{ip}'") from e

    try:
        # Validate the response using Pydantic
        ipquery_response: IPQueryResponse = IPQueryResponse(**response.json())
    except ValidationError as e:
        logger.error("Error validating ipquery response for '%s': %s", ip, e, exc_info=True)
        raise IPQueryError(f"Error validating ipquery response for '{ip}'") from e

    return ipquery_response


def build_ipquery_observable(ipquery_response: IPQueryResponse) -> IPQueryObservable:
    """Parse IPQueryResponse into the custom Observable object"""

    ip_link: str = f"https://api.ipquery.io/{ipquery_response.ip}" if ipquery_response.ip != "Unknown" else "Unknown"

    try:
        ipquery_observable: IPQueryObservable = IPQueryObservable(
            ip=ipquery_response.ip,
            geolocation=f"{ipquery_response.location.city}, {ipquery_response.location.state}",
            country_code=ipquery_response.location.country_code,
            country_name=ipquery_response.location.country,
            isp=ipquery_response.isp.isp,
            asn=ipquery_response.isp.asn,
            is_vpn=ipquery_response.risk.is_vpn,
            is_tor=ipquery_response.risk.is_tor,
            is_proxy=ipquery_response.risk.is_proxy,
            risk_score=ipquery_response.risk.risk_score,
            link=ip_link,
        )
    except ValidationError as e:
        logger.error("Error validating IPQueryObservable: %s", e, exc_info=True)
        raise IPQueryError("Error validating IPQueryObservable") from e

    return ipquery_observable


def run_ipquery_analysis(ip: str, proxies: dict[str, str], ssl_verify: bool = True) -> dict | None:
    """Perform IPQuery analysis."""

    try:
        ipquery_response: IPQueryResponse = query_ipquery(ip, proxies, ssl_verify)
        ipquery_observable: IPQueryObservable = build_ipquery_observable(ipquery_response)
    except IPQueryError:
        logger.error("Error querying IPQuery for '%s'", ip, exc_info=True)
        return None

    return json.loads(ipquery_observable.model_dump_json())
