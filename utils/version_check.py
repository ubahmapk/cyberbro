import json
import logging
import time
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

import requests

from utils.config import DATA_DIR, Secrets, get_config

logger = logging.getLogger(__name__)


class InvalidCachefileError(Exception):
    pass


"""
check_for_new_version() arguments must be hashable to allow for the LRU cache.
So we're re-creating the global PROXIES and SSL_VERIFY variables here
"""
secrets: Secrets = get_config()
PROXIES: dict[str, str] | None = {"https": secrets.proxy_url, "http": secrets.proxy_url} if secrets.proxy_url else None
SSL_VERIFY: bool = secrets.ssl_verify


def get_latest_version_from_cache_file(cache_file: Path) -> str:
    """Check if the cache file exists and is not older than a day.

    Return True if the cache file is valid and recent, False otherwise.
    """

    if not cache_file.exists():
        raise InvalidCachefileError("Cache file does not exist.")

    class CacheData(NamedTuple):
        last_checked: float
        latest_version: str = "unknown"

    try:
        with cache_file.open() as f:
            cache_data: CacheData = CacheData(**json.load(f))
    except json.JSONDecodeError as e:
        print("Cache file is corrupted, fetching latest version.")
        logger.warning("Cache file is corrupted, fetching latest version.")
        raise InvalidCachefileError("Cache file is corrupted.") from e
    except (OSError, TypeError) as e:
        raise InvalidCachefileError("Cache file is not readable.") from e

    if time.time() - cache_data.last_checked > 86400:
        raise InvalidCachefileError("Cache file is too old.")

    return cache_data.latest_version


def get_latest_version_from_updated_cache_file(cache_file: Path) -> str:
    """Update the cache file with the latest version and current time."""

    url: str = "https://api.github.com/repos/stanfrbd/cyberbro/releases/latest"

    if not cache_file.exists():
        cache_file.touch()

    try:
        response = requests.get(url, proxies=PROXIES, verify=SSL_VERIFY, timeout=5)
        response.raise_for_status()
        latest_version: str = response.json().get("tag_name", "")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching latest version: {e}")
        return ""
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON response: {e}")
        return ""

    try:
        with cache_file.open("w") as f:
            json.dump({"last_checked": time.time(), "latest_version": latest_version}, f)
            logger.info(f"Cache file updated with latest version: {latest_version}")
    except OSError as e:
        logger.error(f"Error writing to cache file: {e}")

    return latest_version


@lru_cache
def check_for_new_version(
    current_version: str,
) -> bool:
    """Check if a new version of the application is available."""

    cache_file: Path = DATA_DIR / "version_cache.json"

    # Check if cache file exists and is not older than a day
    try:
        latest_version: str = get_latest_version_from_cache_file(cache_file)
    except InvalidCachefileError:
        latest_version = get_latest_version_from_updated_cache_file(cache_file)

    return latest_version != current_version
