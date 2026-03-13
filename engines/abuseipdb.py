import logging
from contextlib import suppress

import pycountry
from pydantic import ValidationError
from requests.exceptions import JSONDecodeError, RequestException

from models.abuseipdb import AbuseIPDBReport
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class AbuseIPDBEngine(BaseEngine[AbuseIPDBReport]):
    @property
    def name(self):
        return "abuseipdb"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        # AbuseIPDB only supports IPs, so we want it to run AFTER any potential DNS resolution
        return True

    def query_api(self, api_key: str, observable: Observable) -> AbuseIPDBReport:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": observable.value}

        try:
            response = self._make_request(
                url,
                headers=headers,
                params=params,
                timeout=5,
            )
            response.raise_for_status()
        except RequestException as e:
            msg: str = f"AbuseIPDB API error: {e}"
            logger.warning(msg)
            return AbuseIPDBReport(success=False, error=msg)

        try:
            api_response: AbuseIPDBReport = AbuseIPDBReport(**response.json()["data"])
        except (KeyError, ValidationError, JSONDecodeError) as e:
            msg: str = f"AbuseIPDB API response parsing error: {e}"
            logger.warning(msg)
            return AbuseIPDBReport(success=False, error=msg)

        api_response.success = True
        return api_response

    def analyze(self, observable: Observable) -> AbuseIPDBReport:
        api_key: str = self.secrets.abuseipdb

        if not api_key:
            msg: str = "AbuseIPDB API key not set"
            logger.warning(msg)
            return AbuseIPDBReport(success=False, error=msg)

        report: AbuseIPDBReport = self.query_api(api_key, observable)
        if not report.success:
            return report

        # Extract country code and resolve country name
        with suppress(AttributeError):
            report.country_name = pycountry.countries.get(alpha_2=report.country_code).name  # ty:ignore[unresolved-attribute]

        return report

    def create_export_row(self, analysis_result: AbuseIPDBReport | None) -> dict:
        if not analysis_result:
            return {
                "a_ipdb_reports": None,
                "a_ipdb_risk": None,
                "a_ipdb_country": None,
                "a_ipdb_isp": None,
                "a_ipdb_domain": None,
                "a_ipdb_usage_type": None,
                "a_ipdb_is_tor": None,
                "a_ipdb_last_reported": None,
            }
        return {
            "a_ipdb_reports": analysis_result.reports,
            "a_ipdb_risk": analysis_result.risk_score,
            "a_ipdb_country": analysis_result.country_name,
            "a_ipdb_isp": analysis_result.isp,
            "a_ipdb_domain": analysis_result.domain,
            "a_ipdb_usage_type": analysis_result.usage_type,
            "a_ipdb_is_tor": analysis_result.is_tor,
            "a_ipdb_last_reported": analysis_result.last_reported_at,
        }
