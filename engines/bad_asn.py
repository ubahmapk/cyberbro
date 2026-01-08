"""
Bad ASN Check Engine
Checks if an IP's ASN is listed in known bad ASN databases.
Requires ASN data from other engines (ipapi, ipinfo, ipquery).
"""

import logging

from models.base_engine import BaseEngine
from utils.bad_asn_manager import check_asn

logger = logging.getLogger(__name__)


class BadASNEngine(BaseEngine):
    """
    Engine that checks if an IP's ASN is listed in malicious ASN databases.
    This engine depends on ASN data from other engines like ipapi, ipinfo, or ipquery.
    """

    @property
    def name(self) -> str:
        return "bad_asn"

    @property
    def supported_types(self) -> list[str]:
        """Supports IPv4 and IPv6 addresses."""
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self) -> bool:
        """
        Execute in Phase 3 (Post-Pivot) to ensure other IP info engines
        (like ipapi, ipinfo, ipquery) have already run and retrieved ASN data.
        """
        return True

    def analyze(self, observable_value: str, observable_type: str, context: dict | None = None) -> dict | None:
        """
        Check if the IP's ASN is listed in bad ASN databases.

        Args:
            observable_value: IP address to check
            observable_type: Should be IPv4 or IPv6
            context: Dictionary containing results from other engines (optional)

        Returns:
            Dictionary with status, source, and details if ASN is malicious, None otherwise
        """
        if not context:
            logger.warning(f"Bad ASN engine called without context for {observable_value}")
            return None

        # Try to extract ASN from various possible engine results
        asn = self._extract_asn_from_context(context)

        if not asn:
            logger.debug(f"No ASN found in context for {observable_value}, skipping Bad ASN check")
            return None

        # Check ASN against bad ASN databases
        result = check_asn(asn)

        if result:
            logger.info(f"Bad ASN detected: {asn} for IP {observable_value} - {result['source']}")
            return result

        # ASN is clean
        logger.debug(f"ASN {asn} for IP {observable_value} is not listed in bad ASN databases")
        return {"status": "clean", "asn": asn, "details": f"ASN {asn} is not listed in bad ASN databases"}

    def _extract_asn_from_context(self, context: dict) -> str | None:
        """
        Extract ASN from results of other engines (ipapi, ipinfo, ipquery, etc.).

        Args:
            context: Dictionary containing results from other engines

        Returns:
            ASN as string (normalized), or None if not found
        """
        # Priority order: ipapi > ipinfo > ipquery (based on reliability)

        # Try ipapi first (uses api.ipapi.is)
        ipapi_data = context.get("ipapi")
        if ipapi_data and isinstance(ipapi_data, dict):
            # ipapi structure: {"asn": {"asn": "AS13335", "org": "..."}}
            asn_obj = ipapi_data.get("asn")
            if asn_obj and isinstance(asn_obj, dict):
                asn = asn_obj.get("asn")
                if asn and asn != "Unknown":
                    # ASN format: "AS13335" (string with AS prefix)
                    asn_str = str(asn).strip()
                    if asn_str.startswith("AS"):
                        asn_str = asn_str[2:]
                    if asn_str and asn_str.isdigit():
                        return asn_str

        # Try ipinfo (uses ipinfo.io)
        ipinfo_data = context.get("ipinfo")
        if ipinfo_data and isinstance(ipinfo_data, dict):
            # ipinfo structure: {"asn": "AS13335 Cloudflare, Inc."}
            asn_str = ipinfo_data.get("asn", "")
            if asn_str and isinstance(asn_str, str) and asn_str != "Unknown" and asn_str != "BOGON" and asn_str.startswith("AS"):
                # Extract ASN from format "AS13335 Cloudflare, Inc."
                parts = asn_str.split()
                if len(parts) > 0:
                    asn_num = parts[0][2:]  # Remove "AS" prefix from first part
                    if asn_num and asn_num.isdigit():
                        return asn_num

        # Try ipquery
        ipquery_data = context.get("ipquery")
        if ipquery_data and isinstance(ipquery_data, dict):
            asn = ipquery_data.get("asn")
            if asn:
                return str(asn)

        return None

    def create_export_row(self, analysis_result: dict | None) -> dict:
        """
        Format Bad ASN check result for CSV/Excel export.

        Args:
            analysis_result: Result from analyze() method

        Returns:
            Dictionary with flattened data for export
        """
        if not analysis_result:
            return {
                "bad_asn_status": "N/A",
                "bad_asn_asn": "",
                "bad_asn_source": "",
                "bad_asn_details": "",
            }

        return {
            "bad_asn_status": analysis_result.get("status", "N/A"),
            "bad_asn_asn": analysis_result.get("asn", ""),
            "bad_asn_source": analysis_result.get("source", ""),
            "bad_asn_details": analysis_result.get("details", ""),
        }
