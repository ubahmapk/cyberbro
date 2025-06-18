from engines import (
    abuseipdb,
    abusix,
    alienvault,
    chrome_extension,
    criminalip,
    crowdstrike,
    github,
    google,
    google_dns,
    google_safe_browsing,
    hudsonrock,
    ioc_one,
    ipinfo,
    ipquery,
    microsoft_defender_for_endpoint,
    misp,
    opencti,
    phishtank,
    rdap,
    reverse_dns,
    shodan,
    spur_us_free,
    threatfox,
    urlscan,
    virustotal,
    webscout,
)
from utils.config import Secrets, get_config


def list_engines() -> dict[str, dict[str, str]]:
    """
    Return a list of engines and their descriptions, based on each engine's metadata attributes.
    """

    secrets: Secrets = get_config()

    engines = [
        abuseipdb,
        abusix,
        alienvault,
        chrome_extension,
        criminalip,
        crowdstrike,
        github,
        google,
        google_dns,
        google_safe_browsing,
        hudsonrock,
        ioc_one,
        ipinfo,
        ipquery,
        microsoft_defender_for_endpoint,
        misp,
        opencti,
        phishtank,
        rdap,
        reverse_dns,
        shodan,
        spur_us_free,
        threatfox,
        urlscan,
        virustotal,
        webscout,
    ]

    response: dict[str, dict[str, str]] = {}

    """Only return the engines that are enabled in the configuration."""
    for engine in [engine for engine in engines if engine.NAME in secrets.gui_enabled_engines]:
        response.update(
            {
                engine.NAME: {
                    "label": engine.LABEL,
                    "description": engine.DESCRIPTION,
                    "supports": engine.SUPPORTS,
                    "cost": engine.COST,
                    "api_key_required": engine.API_KEY_REQUIRED,
                    "supported_observable_types": engine.SUPPORTED_OBSERVABLE_TYPES,
                }
            }
        )

    return response
