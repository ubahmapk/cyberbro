import logging
from typing import Any, TypedDict
from urllib.parse import quote

import requests
from pydantic import ValidationError

from models.alienvault_datamodel import OTXReport, Pulse
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from utils.config import QueryError

logger = logging.getLogger(__name__)


class PulseData(TypedDict):
    title: str
    url: str


class AlienVaultEngine(BaseEngine):
    @property
    def name(self):
        return "alienvault"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        """
        Queries the OTX AlienVault API for information about a given observable.
        Reuses the original maintainer's logic for querying and parsing.
        """
        api_key: str = self.secrets.alienvault
        if not api_key:
            logger.error("OTX AlienVault API key is required")
            return None

        try:
            # Reuse the existing query logic
            result: dict = query_alienvault(observable, api_key)

            # Reuse the existing parsing logic
            report: dict = parse_alienvault_response(result)
            return report

        except QueryError:
            logger.warning("Error retrieving or parsing report from AlienVault")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in AlienVault engine: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "alienvault_pulses": None,
                "alienvault_malwares": None,
                "alienvault_adversary": None,
            }

        malware_families = ", ".join(analysis_result.get("malware_families", []))
        adversaries = ", ".join(analysis_result.get("adversary", []))

        return {
            "alienvault_pulses": analysis_result.get("count"),
            "alienvault_malwares": malware_families if malware_families else None,
            "alienvault_adversary": adversaries if adversaries else None,
        }


# --- Original Maintainer's Code / Helper Functions (Preserved) ---


def get_endpoint(observable: Observable) -> str | None:
    # Map observable type to OTX endpoint

    # If it's a URL, extract the domain portion for searching
    if observable.type is ObservableType.URL:
        artifact: str = observable._return_fqdn_from_url()
        observable.type = ObservableType.FQDN
    else:
        artifact = observable.value

    endpoint_map: dict[ObservableType, str] = {
        ObservableType.IPV4: f"/indicators/IPv4/{quote(artifact)}/general",
        ObservableType.IPV6: f"/indicators/IPv6/{quote(artifact)}/general",
        ObservableType.FQDN: f"/indicators/domain/{quote(artifact)}/general",
        ObservableType.SHA1: f"/indicators/file/{quote(artifact)}/general",
        ObservableType.MD5: f"/indicators/file/{quote(artifact)}/general",
        ObservableType.SHA256: f"/indicators/file/{quote(artifact)}/general",
    }

    return endpoint_map.get(observable.type)


def query_alienvault(
    observable: Observable,
    api_key: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict:
    endpoint = get_endpoint(observable)

    if not endpoint:
        raise QueryError(f"Invalid observable type: {observable.type}") from None

    url = f"https://otx.alienvault.com/api/v1{endpoint}"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(url, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.exceptions.RequestException as req_err:
        logger.error("Network error while querying OTX AlienVault: %s", req_err, exc_info=True)
        raise QueryError from req_err

    return result


def parse_alienvault_response(result: dict) -> dict:
    try:
        otx_report: OTXReport = OTXReport(**result)
    except ValidationError as e:
        logger.error("Error validating OTX response")
        raise QueryError from e

    """
    Malware Families

    OTX includes `malware_families` in three different locations:
    - Pulse (MalwareFamily object)
    - Related.Alienvault (string)
    - Related.Other (string)
    """
    report_malware_families: list[str] = []
    report_malware_families.extend(
        [
            family
            for family in otx_report.pulse_info.related.alienvault.malware_families
            if family.lower() not in map(str.lower, report_malware_families)
        ]
    )

    report_malware_families.extend(
        [
            family
            for family in otx_report.pulse_info.related.other.malware_families
            if family.lower() not in map(str.lower, report_malware_families)
        ]
    )

    """
    Adversary
    """
    adversary: set[str] = set(otx_report.pulse_info.related.alienvault.adversary)

    pulses: list[Pulse] = otx_report.pulse_info.pulses
    pulse_data: list[PulseData] = []
    seen_urls: set[str | None] = set()  # Track unique pulse URLs

    # Sort pulses by 'created' timestamp in descending order
    sorted_pulses = sorted(pulses, key=lambda x: x.created, reverse=True)

    for pulse in sorted_pulses:
        if (pulse.name == "Unknown") or (not pulse.id):
            continue

        # Link to default pulse URL if no other more specific link is present
        pulse_url_default_value: str = f"https://otx.alienvault.com/pulse/{pulse.id}"
        pulse_url: str = pulse.references[0] if pulse.references else pulse_url_default_value

        # Skip if this pulse URL has already been seen (excluding None entries)
        if pulse_url != pulse_url_default_value and pulse_url in seen_urls:
            continue

        # Add to seen URLs and include in output
        seen_urls.add(pulse_url)
        pulse_data.append({"title": pulse.name, "url": pulse_url})

        # Add the pulse malware_family to the set
        report_malware_families.extend(
            [
                family.display_name
                for family in pulse.malware_families
                if family.display_name.lower() not in map(str.lower, report_malware_families)
            ]
        )

        if pulse.adversary:
            adversary.add(pulse.adversary)

        # Stop after collecting 5 unique pulses
        if len(pulse_data) >= 5:
            break

    count = len(pulse_data)

    # The original observable is included in the OTXReport object as the "indicator"
    link = f"https://otx.alienvault.com/browse/global/pulses?q={quote(otx_report.indicator)}"
    return {
        "count": count,
        "pulses": pulse_data,
        "malware_families": report_malware_families,
        "adversary": list(adversary),
        "link": link,
    }
