import logging
from collections.abc import Mapping
from typing import Any

import pycountry
from pydantic.dataclasses import dataclass
from requests.exceptions import RequestException
from typing_extensions import override

from models.base_engine import BaseEngine, BaseReport

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class IPInfoReport(BaseReport):
    ip: str = ""
    geolocation: str = ""
    country_code: str = ""
    country_name: str = ""
    hostname: str = ""
    asn: str = ""
    link: str = ""


class IPInfoEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "ipinfo"

    @property
    @override
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    @override
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            url = f"https://ipinfo.io/{observable_value}/json?token={self.secrets.ipinfo}"
            response = self._make_request(url, timeout=5)

            data = response.json()

            # Handle bogon/private IPs explicitly
            if "bogon" in data:
                return IPInfoReport(
                    success=True,
                    ip=observable_value,
                    geolocation="",
                    country_code="",
                    country_name="Bogon",
                    hostname="Private IP",
                    asn="BOGON",
                    link=f"https://ipinfo.io/{observable_value}",
                ).__json__()

            if "ip" in data:
                ip_resp = data.get("ip", "Unknown")
                city = data.get("city", "Unknown")
                region = data.get("region", "Unknown")
                asn_raw = data.get("org", "Unknown")
                country_code = data.get("country", "Unknown")

                # Attempt to resolve country name
                try:
                    country_obj = pycountry.countries.get(alpha_2=country_code)
                    country_name = country_obj.name if country_obj else "Unknown"
                except Exception:
                    country_name = "Unknown"

                return IPInfoReport(
                    success=True,
                    ip=ip_resp,
                    geolocation=f"{city}, {region}",
                    country_code=country_code,
                    country_name=country_name,
                    hostname=data.get("hostname", "Unknown"),
                    asn=asn_raw,
                    link=f"https://ipinfo.io/{ip_resp}",
                ).__json__()

        except RequestException as e:
            logger.error(
                "Error querying ipinfo for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )

        return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {f"ipinfo_{k}": None for k in ["cn", "country", "geo", "asn", "org"]}

        asn_str = analysis_result.get("asn")
        asn_data = asn_str.split(" ", 1) if asn_str else []

        return {
            "ipinfo_cn": analysis_result.get("country_code"),
            "ipinfo_country": analysis_result.get("country_name"),
            "ipinfo_geo": analysis_result.get("geolocation"),
            "ipinfo_asn": asn_data[0] if len(asn_data) > 0 else None,
            "ipinfo_org": asn_data[1] if len(asn_data) > 1 else None,
        }
