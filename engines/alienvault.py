import logging
import requests
import json
from typing import Optional, Dict, Any, List
from urllib.parse import quote

logger = logging.getLogger(__name__)

def query_alienvault(
    observable: str,
    observable_type: str,
    proxies: Dict[str, str],
    ssl_verify: bool = True,
    api_key: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Queries the OTX AlienVault API for information about a given observable (URL, IP, domain, hash).

    Args:
        observable (str): The observable to search for (e.g., URL, IP address, domain, hash).
        observable_type (str): The type of the observable (e.g., "URL", "IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5").
        proxies (dict): A dictionary of proxies to use for the request.
        ssl_verify (bool): Whether to verify SSL certificates.
        api_key (str): OTX AlienVault API key (required).

    Returns:
        dict: A dictionary with "count" (int), "pulses" (list), and "link" (str). For example:
              {
                  "count": 2,
                  "pulses": [
                      {"title": "Malware Campaign", "url": "https://example.com/report", "malware_families": ["Emotet", "TrickBot"]},
                      {"title": "Phishing Alert", "url": None, "malware_families": ["Dridex"]}
                  ],
                  "link": "https://otx.alienvault.com/browse/global/pulses?q=<observable>"
              }
        None: If an error occurs or API key is missing.
    """
    try:
        if not api_key:
            logger.error("OTX AlienVault API key is required")
            return None

        # If it's a URL, extract the domain portion for searching
        if observable_type == "URL":
            domain_part = observable.split("/")[2].split(":")[0]
            observable = domain_part
            observable_type = "FQDN"

        # Validate observable type
        if observable_type not in ["IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5"]:
            logger.error("Unsupported observable type: %s", observable_type)
            return None

        # Map observable type to OTX endpoint
        endpoint_map = {
            "IPv4": f"/indicators/IPv4/{quote(observable)}/general",
            "IPv6": f"/indicators/IPv6/{quote(observable)}/general",
            "FQDN": f"/indicators/domain/{quote(observable)}/general",
            "SHA1": f"/indicators/file/{quote(observable)}/general",
            "MD5": f"/indicators/file/{quote(observable)}/general",
            "SHA256": f"/indicators/file/{quote(observable)}/general"
        }

        endpoint = endpoint_map.get(observable_type)
        if not endpoint:
            logger.error("Invalid observable type: %s", observable_type)
            return None

        url = f"https://otx.alienvault.com/api/v1{endpoint}"
        headers = {"X-OTX-API-KEY": api_key}

        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5
        )
        response.raise_for_status()

        result = response.json()
        pulses = result.get("pulse_info", {}).get("pulses", [])

        pulse_data = []
        if isinstance(pulses, list):
            # Sort pulses by 'created' timestamp in descending order
            sorted_pulses = sorted(
                pulses,
                key=lambda x: x.get("created", ""),
                reverse=True
            )

            for pulse in sorted_pulses[:5]:  # Limit to 5 most recent pulses
                pulse_name = pulse.get("name", "Unknown")
                if pulse_name == "Unknown":
                    continue

                # Get pulse URL from the first reference, or None if not available
                references = pulse.get("references", [])
                pulse_url = references[0] if references else None

                # Get malware families using display_name
                malware_families = []
                for malware in pulse.get("malware_families", []):
                    display_name = malware.get("display_name")
                    if display_name:
                        malware_families.append(display_name)

                pulse_data.append({
                    "title": pulse_name,
                    "url": pulse_url,
                    "malware_families": malware_families
                })

            count = len(pulses)
        else:
            count = 0

        link = f"https://otx.alienvault.com/browse/global/pulses?q={quote(observable)}"
        return {
            "count": count,
            "pulses": pulse_data,
            "link": link
        }

    except Exception as e:
        logger.error("Error querying OTX AlienVault for '%s': %s", observable, e, exc_info=True)
        return None