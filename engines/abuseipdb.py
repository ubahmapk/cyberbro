import logging
from contextlib import suppress

import pycountry
from pydantic import Field, ValidationError, model_validator
from requests.exceptions import JSONDecodeError, RequestException

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from models.report import BaseReport

logger = logging.getLogger(__name__)


class AbuseIPDBReport(BaseReport):
    ip_address: str = Field(alias="ipAddress", default="")
    # is_public: bool = Field(alias="isPublic")
    # ip_version: int = Field(alias="ipVersion")
    is_whitelisted: bool = Field(alias="isWhitelisted", default=False)
    risk_score: int = Field(alias="abuseConfidenceScore", default=0)
    is_tor: bool = Field(alias="isTor", default=False)
    # hostnames: list[str] = Field(default_factory=list[str])
    country_code: str = Field(alias="countryCode", default="")
    country_name: str = "Unknown"
    # usage_type: str = Field(alias="usageType", default="")
    domain: str = ""
    isp: str = ""
    reports: int = Field(alias="totalReports", default=0)
    # num_distinct_users: int = Field(alias="numDistinctUsers", default=0)
    last_reported_at: str = Field(alias="lastReportedAt", default="")
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def __generate_link__(self):
        self.link = f"https://www.abuseipdb.com/check/{self.ip_address}"
        return self


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
            "a_ipdb_reports": analysis_result.get("reports"),
            "a_ipdb_risk": analysis_result.get("risk_score"),
            "a_ipdb_country": analysis_result.get("country_name"),
            "a_ipdb_isp": analysis_result.get("isp"),
            "a_ipdb_domain": analysis_result.get("domain"),
            "a_ipdb_usage_type": analysis_result.get("usage_type"),
            "a_ipdb_is_tor": analysis_result.get("is_tor"),
            "a_ipdb_last_reported": analysis_result.get("last_reported_at"),
        }
