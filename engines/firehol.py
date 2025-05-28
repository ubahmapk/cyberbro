import ipaddress
import logging
import time
from pathlib import Path

import requests
from requests.exceptions import HTTPError

from utils.config import Secrets, get_config

BASE_DIR: Path = Path.resolve(Path(__file__).parent.parent)

logger = logging.getLogger(__name__)


def get_firehol_config() -> tuple[str, Path, int]:
    secrets: Secrets = get_config()

    firehol_url: str = secrets.firehol_url
    firehol_cache_timeout: int = secrets.firehol_cache_timeout
    firehol_blacklist_file: Path = Path(BASE_DIR / firehol_url.split("/")[-1])

    return firehol_url, firehol_blacklist_file, firehol_cache_timeout


def download_firehol_blacklist(
    firehol_url: str, blacklist_file: Path, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> None:
    """Download the Firehol Level3 blacklist and save it to the specified file."""

    try:
        response = requests.get(url=firehol_url, proxies=proxies, verify=ssl_verify)
        response.raise_for_status()
    except HTTPError:
        logger.error("Error retrieving Firehol Level3 list")
        return None

    """
    Explode any CIDR entries in the list
    """
    ip_addresses: list[str] = []
    for line in response.iter_content(decode_unicode=True):
        if line.startswith("#") or not line.strip():
            continue
        if "/" in line:
            net_range: list[str] = [str(host) for host in ipaddress.ip_network(line.strip()).hosts()]
            [ip_addresses.append(ip) for ip in net_range]
        else:
            ip_addresses.append(line.strip())

    try:
        with blacklist_file.open("w") as f:
            for ip in sorted(ip_addresses):
                f.write(f"{ip}\n")
    except OSError:
        logger.error(f"Error saving response to file {blacklist_file}")

    logger.info(f"Saved updated firehol_level3 list to {blacklist_file}")
    return None


def firehole_blacklist_file_valid(blacklist_file: Path, cache_seconds: int) -> bool:
    """Check if the Firehol blacklist file is valid based on its last modified time."""

    if not blacklist_file.exists():
        return False

    return (time.time() - blacklist_file.stat().st_mtime) < cache_seconds


def run_firehol_analysis(
    observable: str, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, bool]:
    """Perform Firehol analysis."""

    firehol_url, blacklist_file, firehol_cache_timeout = get_firehol_config()

    results: dict[str, bool] = {"firehol": False}

    if not firehole_blacklist_file_valid(blacklist_file, firehol_cache_timeout):
        logger.info("Firehol blacklist file is outdated or does not exist. Downloading a new one.")
        download_firehol_blacklist(firehol_url, blacklist_file, proxies, ssl_verify)

    try:
        with blacklist_file.open("r") as f:
            if observable in f.read():
                results.update({"firehol": True})
    except OSError as e:
        logger.error(f"Error reading Firehol blacklist file: {e}")

    return results


if __name__ == "__main__":
    # Example usage
    observable: str = input("Enter an IP address: ")

    results: dict[str, bool] = run_firehol_analysis(observable)
    print(f"Firehol analysis results for {observable}: {results}")
