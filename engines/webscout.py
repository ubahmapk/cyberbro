import logging
import requests
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def query_webscout(ip: str, api_key: str, proxies: Dict[str, str], ssl_verify: bool = True) -> Optional[Dict[str, Any]]:
    """
    Queries the IP information from the webscout.io API.

    Args:
        ip (str): The IP address to query.
        api_key (str): The API key for webscout.io.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing extracted information:
            {
                "ip": ...,
                "risk_score": ...,
                "location": "country_name, region",
                "country_code": ...,
                "country_name": ...,
                "hostnames": ...,
                "domains_on_ip": ...,
                "operator": ...,
                "network_type": ...,
                "network_provider": ...,
                "network_service": ...,
                "network_service_region": ...,
                "network_provider_services": ...,
                "behavior": ...,
                "as_org": ...,
                "asn": ...,
                "provider_description": ...,
                "operator_description": ...,
                "network_risk_score": ...,
                "network_range": ...,
                "is_private": ...,
                "open_ports": ...
            }
        None: If an error occurs or 'status' key isn't 'success'.
    """
    try:
        url = f"https://api.webscout.io/query/ip/{ip}?apikey={api_key}"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if data.get("status") == "success":
            ip_resp = data["data"].get("ip", "Unknown")
            risk_score = data["data"].get("risk_score", "Unknown")
            country_name = data["data"]["location"].get("country_name", "Unknown")
            country_code = data["data"]["location"].get("country_iso", "Unknown")
            region = data["data"]["location"].get("region", "Unknown")
            hostnames = data["data"].get("hostnames", [])
            domains_on_ip = data["data"].get("domains_on_ip", "Unknown")
            operator = data["data"].get("operator", "Unknown")
            network_type = data["data"].get("network_type", "Unknown")
            network_provider = data["data"].get("network_provider", "Unknown")
            network_service = data["data"].get("network_service", "Unknown")
            network_service_region = data["data"].get("network_service_region", "Unknown")
            network_provider_services = data["data"].get("network_provider_services", [])
            behavior = data["data"].get("behavior", [])
            as_org = data["data"].get("as_org", "Unknown")
            asn = data["data"].get("asn", [])
            provider_description = data["data"].get("provider_description", "Unknown")
            operator_description = data["data"].get("operator_description", "Unknown")
            network_risk_score = data["data"].get("network_risk_score", "Unknown")
            network_range = data["data"].get("network_range", "Unknown")
            is_private = data["data"].get("is_private", False)
            open_ports = data["data"].get("open_ports", [])

            return {
                "ip": ip_resp,
                "risk_score": risk_score,
                "location": f"{country_name}, {region}",
                "country_code": country_code,
                "country_name": country_name,
                "hostnames": hostnames,
                "domains_on_ip": domains_on_ip,
                "operator": operator,
                "network_type": network_type,
                "network_provider": network_provider,
                "network_service": network_service,
                "network_service_region": network_service_region,
                "network_provider_services": network_provider_services,
                "behavior": behavior,
                "as_org": as_org,
                "asn": asn,
                "provider_description": provider_description,
                "operator_description": operator_description,
                "network_risk_score": network_risk_score,
                "network_range": network_range,
                "is_private": is_private,
                "open_ports": open_ports
            }

    except Exception as e:
        logger.error("Error querying webscout for '%s': %s", ip, e, exc_info=True)

    return None