import json
import logging

import requests
from pydantic import ValidationError
from requests.exceptions import JSONDecodeError

from models.base_engine import BaseEngine
from models.ipapi import IpapiReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class IPAPIEngine(BaseEngine[IpapiReport]):
    @property
    def name(self):
        return "ipapi"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable: Observable) -> IpapiReport:
        url = "https://api.ipapi.is"
        headers = {"Content-Type": "application/json"}
        payload = {"q": observable.value}

        # Validate API key (should be non-empty and 20 characters)
        if self.secrets.ipapi and len(self.secrets.ipapi) == 20:
            payload["key"] = self.secrets.ipapi
        else:
            if self.secrets.ipapi:
                logger.warning(
                    "ipapi API key format is invalid, querying without API key for '%s'",
                    observable.value,
                )
            else:
                logger.warning(
                    "Be careful, you don't use API key for ipapi, rate limit"
                    f"can happen more often (query: '{observable.value}')",
                )

        try:
            response = self._make_request_post(
                url,
                headers=headers,
                data=json.dumps(payload),
                timeout=5,
            )
            data = response.json()
        except requests.exceptions.RequestException as e:
            msg = f"Error querying ipapi for '{observable.value}': {e!s}"
            logger.error(msg)
            return IpapiReport(success=False, error=msg)
        except JSONDecodeError as e:
            msg = f"Invalid JSON response from ipapi for '{observable.value}': {e!s}"
            logger.error(msg)
            return IpapiReport(success=False, error=msg)

        if "ip" not in data:
            msg = f"No IP in response from ipapi for '{observable.value}'"
            logger.warning(msg)
            return IpapiReport(success=False, error=msg)

        try:
            report: IpapiReport = IpapiReport(**data)
        except ValidationError as e:
            msg = f"Invalid ipapi response for '{observable.value}': {e!s}"
            logger.error(msg)
            return IpapiReport(success=False, error=msg)

        return report

    def create_export_row(self, analysis_result: IpapiReport | None) -> dict:
        if not analysis_result or not analysis_result.success:
            return {
                f"ipapi_{k}": None
                for k in [
                    "ip",
                    "is_vpn",
                    "is_tor",
                    "is_proxy",
                    "is_abuser",
                    "city",
                    "state",
                    "country",
                    "country_code",
                    "asn",
                    "org",
                    "vpn_service",
                    "vpn_url",
                ]
            }

        return {
            "ipapi_ip": analysis_result.ip,
            "ipapi_is_vpn": analysis_result.is_vpn,
            "ipapi_is_tor": analysis_result.is_tor,
            "ipapi_is_proxy": analysis_result.is_proxy,
            "ipapi_is_abuser": analysis_result.is_abuser,
            "ipapi_city": analysis_result.location.city,
            "ipapi_state": analysis_result.location.state,
            "ipapi_country": analysis_result.location.country,
            "ipapi_country_code": analysis_result.location.country_code,
            "ipapi_asn": analysis_result.asn.asn,
            "ipapi_org": analysis_result.asn.org,
            "ipapi_vpn_service": analysis_result.vpn.service,
            "ipapi_vpn_url": analysis_result.vpn.url,
        }
