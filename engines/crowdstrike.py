import logging
from datetime import datetime, timezone
from urllib.parse import urljoin

from falconpy import APIHarnessV2

from models.datatypes import ObservableMap, Proxies, Report
from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

NAME: str = "crowdstrike"
LABEL: str = "CrowdStrike"
SUPPORTS: list[str] = ["hash", "IP", "domain", "URL"]
DESCRIPTION: str = "Checks CrowdStrike for IP, domain, URL, hash, paid API key required with Flacon XDR and Falcon Intelligence licence"  # noqa: E501
COST: str = "Paid"
API_KEY_REQUIRED: bool = True
MIGRATED: bool = True


def map_observable_type(observable_type: str) -> str | None:
    """
    Convert Cyberbro type to Crowdstrike type

    Args:
        obserable_type (str): Cyberbro observable type

    Returns:
        (str | None): Crowdstrike observable type, or None
    """

    match observable_type:
        # why do we need to .lower() IPv4 and IPv6 types?
        case "MD5" | "SHA256" | "SHA1" | "IPv4" | "IPv6":
            return observable_type.lower()
        case "FQDN" | "URL":
            return "domain"
        case _:
            logger.warning(f"Unsupported observable type: {observable_type}")
            return None


def generate_ioc_id(observable: str, observable_type: str) -> str | None:
    """
    Convert Cyberbro observable type to Crowdstrike IOC ID.

    Args:
        observable (str): Cyberbro observable
        observable_type (str): Cyberbro observable type

    Returns:
        (str | None): Crowdstrike IOC ID
    """

    match observable_type:
        case "domain":
            return f"domain_{observable}"
        case "ipv4" | "ipv6":
            return f"ip_address_{observable}"
        case "md5":
            return f"hash_md5_{observable}"
        case "sha256":
            return f"hash_sha256_{observable}"
        case "sha1":
            return f"hash_sha1_{observable}"
        case _:
            logger.warning(f"Unsupported observable type for IOC ID generation: {observable_type}")
            return None


def get_falcon_client(client_id: str, client_secret: str, proxies: Proxies, ssl_verify: bool = True) -> APIHarnessV2:
    """
    Return a Falcon client object.

    Args:
        client_id (str): The client ID for CrowdStrike API authentication.
        client_secret (str): The client secret for CrowdStrike API authentication.
        falcon_url (str): The base URL for the CrowdStrike Falcon API.
        proxies (Proxies): Proxy mapping
        ssl_verify (bool): Whether to verify SSL certificates

    Returns:
        (APIHarnessV2): Crowdstrike API client
    """

    return APIHarnessV2(
        client_id=client_id,
        client_secret=client_secret,
        proxy=proxies,
        user_agent="cyberbro",
        ssl_verify=ssl_verify,
        timeout=5,
    )


def run_engine(
    observable_dict: ObservableMap,
    proxies: Proxies,
    ssl_verify: bool = True,
) -> Report | None:
    """
    Queries CrowdStrike Falcon for information about a given observable.

    Args:
        observable_dict (ObservableMap): The observable mapping object, including
            the name and type to query.
        ssl_verify (bool): Whether to verify SSL certificates.
        proxies (Dict[str, str]): Proxy settings for the API client.

    Returns:
        (Report | None): A Report object with the query results or None if an error occurs.
    """

    secrets: Secrets = get_config()
    client_id: str = secrets.crowdstrike_client_id
    client_secret: str = secrets.crowdstrike_client_secret
    falcon_url: str = secrets.crowdstrike_falcon_base_url
    result: Report = {}

    if not client_id or not client_secret or not falcon_url:
        logger.error("CrowdStrike client ID, secret, and base URL are not configured.")
        return None

    observable_type: str = observable_dict["type"]
    observable: str = observable_dict["value"]

    try:
        falcon: APIHarnessV2 = get_falcon_client(client_id, client_secret, proxies, ssl_verify)

        # Ensure the URL is properly formatted
        falcon_url: str = urljoin(falcon_url, "/").rstrip("/")

        if observable_type == "URL":
            observable = observable.split("/")[2].split(":")[0]

        observable = observable.lower()

        # What happens in Falcon if the observable_type is None?
        observable_type = map_observable_type(observable_type)

        # I don't have access to CrowdStrike, but it looks like the response is a dict, natively?
        # Does this need to be converted via .json()?
        response: dict = falcon.command("indicator_get_device_count_v1", type=observable_type, value=observable)
        logger.debug("Falcon response: %s", response)

        if response["status_code"] != 200:
            logger.debug("Indicator not found: %s", response["body"]["errors"][0]["message"])
            result = {"device_count": 0}
        else:
            data: dict = response["body"]["resources"][0]
            result = {"device_count": data.get("device_count", 0)}

        id_to_search = generate_ioc_id(observable, observable_type)
        request_body = {"ids": [id_to_search]}

        response = falcon.command("GetIntelIndicatorEntities", body=request_body)
        logger.debug("GetIntelIndicatorEntities response: %s", response)

        if response["status_code"] != 200 or not response["body"]["resources"]:
            logger.debug("Indicator not found or error in response: %s", response)
            result.update(
                {
                    "indicator_found": False,
                    "published_date": "",
                    "last_updated": "",
                    "actors": [],
                    "malicious_confidence": "",
                    "threat_types": [],
                    "kill_chain": [],
                    "malware_families": [],
                    "vulnerabilities": [],
                    "link": f"{falcon_url}/search/?term=_all%3A~%27{observable}%27",
                }
            )
            return result

        resource = response["body"]["resources"][0]
        result.update(
            {
                "indicator_found": True,
                "published_date": datetime.fromtimestamp(resource.get("published_date", 0), tz=timezone.utc).strftime(
                    "%Y-%m-%d"
                ),
                "last_updated": datetime.fromtimestamp(resource.get("last_updated", 0), tz=timezone.utc).strftime(
                    "%Y-%m-%d"
                ),
                "actors": resource.get("actors", []),
                "malicious_confidence": resource.get("malicious_confidence", ""),
                "threat_types": resource.get("threat_types", []),
                "kill_chain": resource.get("kill_chains", []),
                "malware_families": resource.get("malware_families", []),
                "vulnerabilities": resource.get("vulnerabilities", []),
                "link": f"{falcon_url}/search/?term=_all%3A~%27{observable}%27",
            }
        )

        return result

    except Exception as e:
        logger.error(
            "Error querying CrowdStrike Falcon for '%s': %s",
            observable,
            e,
            exc_info=True,
        )
        return None
