import json
import logging

import requests
from pydantic import BaseModel, Field

# from dataclasses import asdict, dataclass, field
from requests.exceptions import HTTPError

from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

"""
Criminal IP API integration for retrieving suspicious information about IP addresses.

API info for Suspicious Info Report aavailable at https://www.criminalip.io/developer/api/get-ip-suspicious-info
"""

class OpenPort(BaseModel):
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None

    def __str__(self):
        message: str = (
            f"Port {self.port}\n"
            f"Vulnerability: {self.is_vulnerability}\n"
            f"Product Name: {self.product_name}\n"
            f"Product Version: {self.product_version}\n"
            f"Protocol: {self.protocol}\n"
            f"Socket Type: {self.socket_type}\n"
            f"Confirmed Time: {self.confirmed_time}"
        )

        return message


class IDSAlert(BaseModel):
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None

    def __str__(self) -> str:
        message: str = (
            f"Classification: {self.classification}\n"
            f"Confirmed Time: {self.confirmed_time}\n"
            f"Message: {self.message}\n"
            f"Source System: {self.source_system}\n"
            f"URL: {self.url}"
        )

        return message


class CurrentOpenedPorts(BaseModel):
    count: int
    data: list[OpenPort] = Field(default_factory=list)

    def __str__(self) -> str:
        """Return a string representation of the current opened ports."""

        message: str = ()
        message: str = f"Count: {self.count}\n"

        for port in self.data:
            message += str(port) + "\n"

        return message


class IDSAlerts(BaseModel):
    count: int
    data: list[IDSAlert] = Field(default_factory=list)


class Issues(BaseModel):
    is_vpn: bool = False
    is_proxy: bool = False
    is_cloud: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_darkweb: bool = False
    is_scanner: bool = False
    is_snort: bool = False
    is_anonymous_vpn: bool = False

    def __str__(self) -> str:
        message: str = (
            f"VPN: {self.is_vpn}\n"
            f"Proxy: {self.is_proxy}\n"
            f"Cloud: {self.is_cloud}\n"
            f"Tor: {self.is_tor}\n"
            f"Hosting: {self.is_hosting}\n"
            f"Mobile: {self.is_mobile}\n"
            f"DarkWeb: {self.is_darkweb}\n"
            f"Scanner: {self.is_scanner}\n"
            f"Snort: {self.is_snort}\n"
            f"Anonymous VPN: {self.is_anonymous_vpn}"
        )

        return message


class WhoisRecord(BaseModel):
    as_name: str | None = None
    as_no: int | None = None
    city: str | None = None
    region: str | None = None
    org_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    org_country_code: str | None = None
    confirmed_time: str | None = None

    def __str__(self) -> str:
        message: str = (
            f"AS Name: {self.as_name}\n"
            f"AS Number: {self.as_no}\n"
            f"City: {self.city}\n"
            f"Region: {self.region}\n"
            f"Organization Name: {self.org_name}\n"
            f"Postal Code: {self.postal_code}\n"
            f"Latitude: {self.latitude}\n"
            f"Longitude: {self.longitude}\n"
            f"Organization Country Code: {self.org_country_code}\n"
            f"Confirmed Time: {self.confirmed_time}"
        )

        return message


class Whois(BaseModel):
    count: int = 0
    data: list[WhoisRecord] = Field(default_factory=list)


class SuspiciousInfoReport(BaseModel):
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts | None = None
    ids: IDSAlerts | None = None
    ip: str = ""
    issues: Issues | None = None
    representative_domain: str = ""
    score: dict[str, str] = Field(default_factory=dict)
    status: int | None = None
    whois: Whois | None = None

    def __str__(self) -> str:
        message: str = (
            f"Abuse Record Count: {self.abuse_record_count}\n"
            f"Current Opened Port: {self.current_opened_port}\n"
            f"IDS: {self.ids}\n"
            f"IP: {self.ip}\n"
            f"Issues: {self.issues}\n"
            f"Representative Domain: {self.representative_domain}\n"
            f"Score: {self.score}\n"
            f"Status: {self.status}\n"
            f"Whois: {self.whois}"
        )

        return message


base_url: str = "https://api.criminalip.io"


def retrieve_api_key() -> str:
    """Retrieve the API key from the secrets config."""

    secrets: Secrets = get_config()

    api_key: str = secrets.criminalip_api_key

    return api_key


def get_summary_ip_report(api_key: str, observable: str) -> dict | None:
    """Retrieve 'Summary IP' report."""

    url: str = "/v1/asset/ip/report/summary"
    params: dict = {"ip": observable}
    headers: dict = {"x-api-key": f"{api_key}"}

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
    except HTTPError as e:
        logger.error(
            f"Error retrieving Criminal IP Summary report for {observable}: {e}",
            exc_info=True,
        )
        return None

    return response.json()


def get_suspicious_info_report(
    api_key: str,
    observable: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> SuspiciousInfoReport | None:
    """Retrieve 'Suspicious Info' Report."""

    url: str = f"{base_url}/v2/feature/ip/suspicious-info"
    params: dict = {"ip": observable}
    headers: dict = {"x-api-key": f"{api_key}"}

    try:
        response = requests.get(
            url, params=params, headers=headers, proxies=proxies, verify=ssl_verify
        )
        response.raise_for_status()
    except HTTPError as e:
        logger.error(
            f"Error retrieving Criminal IP Suspicious Info report for {observable}: {e}",
            exc_info=True,
        )
        return None

    """
    suspicious_info_report: SuspiciousInfoReport = from_dict(
        data_class=SuspiciousInfoReport, data=response.json()
    )
    """
    suspcious_info_report: SuspiciousInfoReport = SuspiciousInfoReport(
        **response.json()
    )

    return suspcious_info_report


def run_criminal_ip_analysis(
    observable: str, proxies: dict[str, str], ssl_verify: bool
) -> dict | None:
    """Perform Criminal IP analysis."""

    api_key: str = retrieve_api_key()

    if not api_key:
        logger.error("API key for CriminalIP engine is not configured.")
        return None

    if not observable:
        logger.error("No observable provided to CriminalIP engine.")
        return None

    report: SuspiciousInfoReport | None = get_suspicious_info_report(
        api_key, observable, proxies, ssl_verify
    )

    if not report:
        logger.error("Failed to retrieve the report.")
        return None

    return json.loads(report.model_dump_json())


if __name__ == "__main__":
    # Example usage
    api_key: str = retrieve_api_key()
    ssl_verify: bool = False

    if not api_key:
        logger.error("API key is not configured.")
        exit(1)

    observable: str = input("Enter an IP address: ")

    if not observable:
        logger.error("No observable provided.")
        exit(1)

    report: SuspiciousInfoReport | None = get_suspicious_info_report(
        api_key, observable, ssl_verify=ssl_verify
    )

    if report:
        print("Suspicious Info Report:")
        print(report)
    else:
        logger.error("Failed to retrieve the report.")
