import logging
from typing import Any

from pydantic import ValidationError
from requests.exceptions import RequestException

from models.base_engine import BaseEngine
from models.ipapi import IpapiReport, IpapiResponse
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class IPAPIEngine(BaseEngine):
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
        data = {"q": observable.value}

        # Validate API key (should be non-empty and 20 characters)
        if self.secrets.ipapi and len(self.secrets.ipapi) == 20:
            # Use API key if it matches the expected length
            data["key"] = self.secrets.ipapi
        else:
            # Don't use API key if it doesn't match the format
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
            response = self._make_request(
                url,
                params=data,
                headers=headers,
                timeout=5,
            )
            response.raise_for_status()
        except RequestException as e:
            msg: str = f"Error querying ipapi for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return IpapiReport(success=False, error=msg)

        try:
            api_response = IpapiResponse.model_validate(response.json())
        except ValidationError as e:
            msg: str = f"Error validating IPAPI response for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return IpapiReport(success=False, error=msg)

        if not api_response.ip:
            msg = f"No IP in IPAPI response for {observable.value}"
            logger.error(msg)
            return IpapiReport(success=False, error=msg)

        return IpapiReport(
            success=True,
            ip=api_response.ip,
            location=api_response.location.city,
            country=api_response.location.country,
            asn=api_response.asn.asn,
        )

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
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

        location_data = analysis_result.get("location", {})
        asn_data = analysis_result.get("asn", {})
        vpn_data = analysis_result.get("vpn", {})

        return {
            "ipapi_ip": analysis_result.get("ip"),
            "ipapi_is_vpn": analysis_result.get("is_vpn"),
            "ipapi_is_tor": analysis_result.get("is_tor"),
            "ipapi_is_proxy": analysis_result.get("is_proxy"),
            "ipapi_is_abuser": analysis_result.get("is_abuser"),
            "ipapi_city": location_data.get("city"),
            "ipapi_state": location_data.get("state"),
            "ipapi_country": location_data.get("country"),
            "ipapi_country_code": location_data.get("country_code"),
            "ipapi_asn": asn_data.get("asn"),
            "ipapi_org": asn_data.get("org"),
            "ipapi_vpn_service": vpn_data.get("service"),
            "ipapi_vpn_url": vpn_data.get("url"),
        }
