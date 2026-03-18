import logging

from pydantic import ValidationError
from requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
)

from models.base_engine import BaseEngine
from models.criminalip import CriminalIpReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


base_url: str = "https://api.criminalip.io"


# --- New Engine Class Implementation ---


class CriminalIPEngine(BaseEngine[CriminalIpReport]):
    @property
    def name(self):
        return "criminalip"

    @property
    def supported_types(self) -> ObservableType:
        """
        I'm seeing errors with IPv6 addresses, and not finding any
        documentation the API site that says CriminalIP actually supports
        IPv6 after all.
        """
        return ObservableType.IPV4

    @property
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    def analyze(self, observable: Observable) -> CriminalIpReport:
        """Perform Criminal IP analysis using the preserved helper/models."""

        api_key: str = self.secrets.criminalip_api_key

        if not api_key:
            logger.error("API key for CriminalIP engine is not configured.")
            return CriminalIpReport(
                success=False, error="API key for CriminalIP engine is not configured."
            )

        url: str = f"{base_url}/v2/feature/ip/suspicious-info"
        params: dict = {"ip": observable.value}
        headers: dict = {"x-api-key": f"{self.secrets.criminalip_api_key}"}

        try:
            response = self._make_request(url, params=params, headers=headers)
            response.raise_for_status()
        except (ReadTimeout, ConnectTimeout):
            msg: str = f"Timeout occurred while querying CriminalIP for {observable.value}."
            logger.error(msg)
            return CriminalIpReport(success=False, error=msg)
        except HTTPError as e:
            msg: str = f"Error querying CriminalIP for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return CriminalIpReport(success=False, error=msg)

        try:
            report: CriminalIpReport = CriminalIpReport(**response.json())
        except JSONDecodeError as e:
            msg: str = f"Invalid JSON response from CriminalIP for {observable.value}: {e}"
            logger.error(msg, exc_info=True)
            return CriminalIpReport(success=False, error=msg)
        except ValidationError as e:
            msg: str = (
                f"Error validating Criminal IP Suspicious Info report for {observable.value}: {e}"
            )
            logger.error(msg, exc_info=True)
            return CriminalIpReport(success=False, error=msg)

        return report

    def create_export_row(self, analysis_result: CriminalIpReport | None) -> dict:
        if not analysis_result or not analysis_result.score:
            return {"cip_score_inbound": None, "cip_score_outbound": None, "cip_abuse_count": None}

        return {
            "cip_score_inbound": analysis_result.score.inbound,
            "cip_score_outbound": analysis_result.score.outbound,
            "cip_abuse_count": analysis_result.abuse_record_count,
        }
