import logging
from datetime import datetime, timezone
from urllib.parse import urljoin

from falconpy import APIHarnessV2, Result, SDKError  # Assuming falconpy is installed

from models.base_engine import BaseEngine
from models.crowdstrike import CrowdstrikeReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


def _format_time(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


class CrowdstrikeEngine(BaseEngine[CrowdstrikeReport]):
    @property
    def name(self):
        return "crowdstrike"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.FQDN
            | ObservableType.URL
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
        )

    def _map_observable_type(self, observable_type: ObservableType) -> str:
        match observable_type:
            case ObservableType.FQDN | ObservableType.URL:
                return "domain"
            case ObservableType.IPV4:
                return "ipv4"
            case ObservableType.IPV6:
                return "ipv6"
            case ObservableType.MD5:
                return "md5"
            case ObservableType.SHA256:
                return "sha256"
            case ObservableType.SHA1:
                return "sha1"
            case _:
                raise ValueError(f"Unsupported observable type: {observable_type}")

    def _generate_ioc_id(self, observable_value: str, mapped_type: str) -> str:
        match mapped_type:
            case "domain":
                prefix: str = "domain_"
            case "ipv4" | "ipv6":
                prefix = "ip_address_"
            case "md5":
                prefix = "hash_md5_"
            case "sha256":
                prefix = "hash_sha256_"
            case "sha1":
                prefix = "hash_sha1_"
            case _:
                raise ValueError(f"Unsupported mapped type: {mapped_type}")

        return f"{prefix}{observable_value}"

    def _get_falcon_client(self) -> APIHarnessV2:
        return APIHarnessV2(
            client_id=self.secrets.crowdstrike_client_id,
            client_secret=self.secrets.crowdstrike_client_secret,
            pythonic=True,
            proxy=self.proxies,
            user_agent="cyberbro",
            ssl_verify=self.ssl_verify,
            timeout=5,
        )

    def analyze(self, observable: Observable) -> CrowdstrikeReport:
        if not all(
            (
                self.secrets.crowdstrike_client_id,
                self.secrets.crowdstrike_client_secret,
                self.secrets.crowdstrike_falcon_base_url,
            )
        ):
            return CrowdstrikeReport(success=False, error="CrowdStrike Falcon not fully configured")

        try:
            falcon = self._get_falcon_client()
        except Exception as e:
            msg: str = f"Error initializing CrowdStrike client: {e!s}"
            logger.error(msg)
            return CrowdstrikeReport(success=False, error=msg)

        falcon_url: str = urljoin(self.secrets.crowdstrike_falcon_base_url, "/").rstrip("/")

        if observable.type is ObservableType.URL:
            value: str = observable._return_fqdn_from_url()
        else:
            value: str = observable.value

        value = value.lower()

        try:
            mapped_type: str = self._map_observable_type(observable.type)
        except ValueError as e:
            return CrowdstrikeReport(success=False, error=str(e))

        report: CrowdstrikeReport = CrowdstrikeReport()

        # 1. Get device count
        try:
            response: Result = falcon.command(
                "indicator_get_device_count_v1", type=mapped_type, value=value
            )
        except SDKError as e:
            msg: str = f"Error retrieving CrowdStrike device count for {observable}: {e!s}"
            logger.error(msg)
            report.device_count = 0

        if response.status_code == 200 and response.data:
            report.device_count = response.data[0].get("device_count", 0)

        # 2. Get Intel Indicators
        id_to_search: str = self._generate_ioc_id(value, mapped_type)
        request_body: dict[str, list[str]] = {"ids": [id_to_search]}

        try:
            response = falcon.command("GetIntelIndicatorEntities", body=request_body)
            if response.status_code != 200 or not response.data:
                # Default indicator_found is False
                return report
        except SDKError as e:
            msg: str = f"Error retrieving CrowdStrike intel indicators for {observable}: {e!s}"
            logger.error(msg)
            return CrowdstrikeReport(success=False, error=msg)

        report.link = f"{falcon_url}/search/?term=_all%3A~%27{value}%27"

        resource: dict = response.data[0]
        report.success = True
        report.indicator_found = True
        report.published_date = _format_time(resource.get("published_date", 0))
        report.last_updated = _format_time(resource.get("last_updated", 0))
        report.actors = resource.get("actors", [])
        report.malicious_confidence = resource.get("malicious_confidence", "")
        report.threat_types = resource.get("threat_types", [])
        report.kill_chain = resource.get("kill_chains", [])
        report.malware_families = resource.get("malware_families", [])
        report.vulnerabilities = resource.get("vulnerabilities", [])

        return report

    def create_export_row(self, analysis_result: CrowdstrikeReport | None) -> dict:
        if not analysis_result:
            return {
                f"cs_{k}": None
                for k in [
                    "cs_device_count",
                    "cs_actor",
                    "cs_confidence",
                    "cs_threat_types",
                    "cs_malwares",
                    "cs_kill_chain",
                    "cs_vulns",
                ]
            }

        return {
            "cs_device_count": analysis_result.device_count,
            "cs_actor": ", ".join(analysis_result.actors),
            "cs_confidence": analysis_result.malicious_confidence,
            "cs_threat_types": ", ".join(analysis_result.threat_types),
            "cs_malwares": ", ".join(analysis_result.malware_families),
            "cs_kill_chain": ", ".join(analysis_result.kill_chain),
            "cs_vulns": ", ".join(analysis_result.vulnerabilities),
        }
