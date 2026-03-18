import logging

import requests
from pydantic import ValidationError
from requests.exceptions import JSONDecodeError

from models.base_engine import BaseEngine
from models.ipinfo import IpInfoReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class IPInfoEngine(BaseEngine[IpInfoReport]):
    @property
    def name(self):
        return "ipinfo"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable: Observable) -> IpInfoReport:

        url = f"https://ipinfo.io/{observable.value}/json"
        params = {"token": self.secrets.ipinfo}

        try:
            response = self._make_request(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            msg: str = f"IPInfo request failed for {observable.value}: {e!s}"
            logger.warning(msg)
            return IpInfoReport(success=False, error=msg)
        except JSONDecodeError as e:
            msg: str = f"Invalid JSON response from IPInfo for {observable.value}: {e!s}"
            logger.warning(msg)
            return IpInfoReport(success=False, error=msg)

        try:
            report: IpInfoReport = IpInfoReport(**data)
        except ValidationError as e:
            msg: str = f"Invalid IPInfo response for {observable.value}: {e!s}"
            logger.warning(msg)
            report = IpInfoReport(success=False, error=msg)

        # Bogons and Private IPs are handled in the model_validator
        return report

    def create_export_row(self, analysis_result: IpInfoReport | None) -> dict:
        if not analysis_result:
            return {f"ipinfo_{k}": None for k in ["cn", "country", "geo", "asn", "org"]}

        asn_data = analysis_result.get("asn").split(" ", 1) if analysis_result.get("asn") else []

        return {
            "ipinfo_cn": analysis_result.get("country_code"),
            "ipinfo_country": analysis_result.get("country_name"),
            "ipinfo_geo": analysis_result.get("geolocation"),
            "ipinfo_asn": asn_data[0] if len(asn_data) > 0 else None,
            "ipinfo_org": asn_data[1] if len(asn_data) > 1 else None,
        }
