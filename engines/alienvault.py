import logging
from urllib.parse import quote

from pydantic import ValidationError
from requests.exceptions import ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout

from models.alienvault import AlienvaultReport, OTXReport, Pulse, PulseData
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from utils.config import QueryError

logger = logging.getLogger(__name__)


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

    def _query_alienvault(
        self,
        observable: Observable,
    ) -> dict:

        # If it's a URL, extract the domain portion for searching
        if observable.type == ObservableType.URL:
            artifact: str = observable._return_fqdn_from_url()
            observable_type: ObservableType = ObservableType.FQDN
        else:
            artifact = observable.value
            observable_type = observable.type

        endpoint = get_endpoint(artifact, observable_type)

        if not endpoint:
            raise QueryError(f"Invalid observable type: {observable_type}") from None

        url = f"https://otx.alienvault.com/api/v1{endpoint}"
        headers = {"X-OTX-API-KEY": self.secrets.alienvault}

        try:
            response = self._make_request(url, headers=headers)
            response.raise_for_status()
            result = response.json()

        except (ReadTimeout, ConnectTimeout) as e:
            msg: str = f"Timeout occurred while querying Alienvault for {observable.value}."
            logger.error(msg)
            raise QueryError from e
        except HTTPError as e:
            msg: str = f"Error querying crt.sh for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            raise QueryError from e
        except JSONDecodeError as e:
            msg: str = (
                f"Unexpected error while parsing JSON response "
                f"from crt.sh for {observable.value}: {e!s}\n"
                f"Response: {response!s}"
            )
            logger.error(msg)
            raise QueryError from e

        return result

    def analyze(self, observable: Observable) -> AlienvaultReport:
        """
        Queries the OTX AlienVault API for information about a given observable.
        """
        if not self.secrets.alienvault:
            msg: str = "OTX AlienVault API key is required"
            logger.error(msg)
            return AlienvaultReport(success=False, error=msg)

        try:
            query_result: dict = self._query_alienvault(observable)
        except QueryError as e:
            msg: str = f"{e!s}"
            logger.error(msg)
            return AlienvaultReport(success=False, error=msg)

        # Reuse the existing parsing logic
        report: AlienvaultReport = parse_alienvault_response(query_result)
        return report

    def create_export_row(self, analysis_result: AlienvaultReport | None) -> dict:
        if not analysis_result:
            return {
                "alienvault_pulses": None,
                "alienvault_malwares": None,
                "alienvault_adversary": None,
            }

        malware_families = ", ".join(analysis_result.malware_families)
        adversaries = ", ".join(analysis_result.adversary)

        return {
            "alienvault_pulses": analysis_result.count,
            "alienvault_malwares": malware_families if malware_families else None,
            "alienvault_adversary": adversaries if adversaries else None,
        }


def get_endpoint(artifact: str, observable_type: ObservableType) -> str | None:
    # Map observable type to OTX endpoint
    endpoint_map: dict[ObservableType, str] = {
        ObservableType.IPV4: f"/indicators/IPv4/{quote(artifact)}/general",
        ObservableType.IPV6: f"/indicators/IPv6/{quote(artifact)}/general",
        ObservableType.FQDN: f"/indicators/domain/{quote(artifact)}/general",
        ObservableType.SHA1: f"/indicators/file/{quote(artifact)}/general",
        ObservableType.MD5: f"/indicators/file/{quote(artifact)}/general",
        ObservableType.SHA256: f"/indicators/file/{quote(artifact)}/general",
    }

    return endpoint_map.get(observable_type)


def parse_alienvault_response(result: dict) -> AlienvaultReport:
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
    report_malware_families: set[str] = set()
    report_malware_families.update(
        f.lower() for f in otx_report.pulse_info.related.alienvault.malware_families
    )
    report_malware_families.update(
        f.lower() for f in otx_report.pulse_info.related.other.malware_families
    )

    """
    Adversary
    """
    adversary: set[str] = set(otx_report.pulse_info.related.alienvault.adversary)

    pulses: list[Pulse] = otx_report.pulse_info.pulses
    pulse_data: set[PulseData] = set()
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
        pulse_data.add(PulseData(title=pulse.name, url=pulse_url))

        # Add the pulse malware_family to the set
        report_malware_families.update(
            family.display_name.lower() for family in pulse.malware_families
        )

        if pulse.adversary:
            adversary.add(pulse.adversary)

        # Stop after collecting 5 unique pulses
        if len(pulse_data) >= 5:
            break

    count = len(pulse_data)

    # The original observable is included in the OTXReport object as the "indicator"
    link = f"https://otx.alienvault.com/browse/global/pulses?q={quote(otx_report.indicator)}"
    return AlienvaultReport(
        success=True,
        count=count,
        pulse_data=pulse_data,
        malware_families=report_malware_families,
        adversary=adversary,
        link=link,
    )
