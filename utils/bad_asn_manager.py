"""
Bad ASN Cache Manager
Downloads and maintains a local cache of known malicious ASNs from public blacklists.
"""

import csv
import logging
import time
from pathlib import Path

import orjson
import requests
from pydantic import ValidationError
from requests.exceptions import RequestException

from models.bad_asn import AsnEntry, AsnSource
from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)

# Load configuration
secrets: Secrets = get_config()

# Network configuration
PROXIES: dict[str, str] = {"https": secrets.proxy_url, "http": secrets.proxy_url}
SSL_VERIFY: bool = secrets.ssl_verify

# Cache file location
CACHE_FILE: Path = Path("data/bad_asn_cache.json")
CACHE_MAX_AGE: int = 24 * 60 * 60  # 24 hours in seconds

# Data sources
SPAMHAUS_URL: str = "https://www.spamhaus.org/drop/asndrop.json"
BRIANHAMA_URL: str = (
    "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
)
LETHAL_FORENSICS_URL: str = "https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/ASN-Blacklist.csv"


def normalize_asn(asn_value: str | int) -> str:
    """
    Normalize ASN to standard format (numeric string without 'AS' prefix).

    Args:
        asn_value: ASN as string or integer (e.g., "AS12345", "12345", 12345)

    Returns:
        Normalized ASN as string (e.g., "12345")
    """
    asn_str: str = str(asn_value).strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]
    return asn_str


def download_spamhaus_asndrop() -> dict[str, AsnEntry]:
    """
    Download and parse Spamhaus ASNDROP list (JSONL format).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading Spamhaus ASNDROP list...")
    result: dict[str, AsnEntry] = {}

    try:
        response = requests.get(SPAMHAUS_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30)
        response.raise_for_status()
    except RequestException as e:
        logger.error(f"Failed to download Spamhaus ASNDROP: {e}")
        return result

    # Parse JSONL format (one JSON object per line)
    lines: list[str] = response.text.strip().split("\n")

    for idx, line in enumerate(lines):
        try:
            entry: dict = orjson.loads(line)
        except orjson.JSONDecodeError as e:
            logger.warning(f"Failed to parse Spamhaus ASNDROP line: {idx}:{line}\nError: {e!s}")
            continue

        if entry.get("type") == "metadata":
            continue

        try:
            new_asn: AsnEntry = AsnEntry(**entry)
            new_asn.sources.add(AsnSource.SPAMHAUS)
        except ValidationError as e:
            logger.warning(f"Failed to validate Spamhaus ASNDROP line: {idx}:{line}\nError: {e!s}")
            continue

        # SPAMHAUS seems to always return ASNs as ints?
        # Not sure yet why we're "normalizing" to a string here
        # asn = normalize_asn(entry.get("asn", ""))

        if not new_asn.asn:
            continue
        result[new_asn.asn] = new_asn

    logger.info(f"Loaded {len(result)} ASNs from Spamhaus ASNDROP")

    return result


def download_brianhama_bad_asn() -> dict[str, AsnEntry]:
    """
    Download and parse Brianhama Bad ASN List (CSV).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading Brianhama Bad ASN List...")
    result: dict[str, AsnEntry] = {}

    try:
        response = requests.get(BRIANHAMA_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30)
        response.raise_for_status()
    except RequestException as e:
        logger.error(f"Failed to Brianhama ASN list: {e}")
        return result

    # Parse CSV
    lines: list[str] = response.text.splitlines()
    reader: csv.DictReader[str] = csv.DictReader(lines)

    for row in reader:
        try:
            entity: AsnEntry = AsnEntry(asn=row.get("ASN"), name=row.get("Entity", ""))
            entity.sources.add(AsnSource.BRIANHAMA)
        except ValidationError as e:
            logger.warning(f"Failed to parse Brianhama ASN entry: {row}\nError: {e!s}")
            continue

        if not entity.asn:
            continue
        result[entity.asn] = entity

    logger.info(f"Loaded {len(result)} ASNs from Brianhama Bad ASN List")

    return result


def download_lethal_forensics_asn() -> dict[str, AsnEntry]:
    """
    Download and parse LETHAL-FORENSICS ASN Blacklist (CSV).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading LETHAL-FORENSICS ASN Blacklist...")
    result: dict[str, AsnEntry] = {}

    try:
        response = requests.get(
            LETHAL_FORENSICS_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30
        )
        response.raise_for_status()
    except RequestException as e:
        logger.error(f"Failed to download Lethal-Forensics ASN Blacklist: {e}")
        return result

    # Parse CSV
    lines: list[str] = response.text.splitlines()
    reader: csv.DictReader[str] = csv.DictReader(lines)

    for row in reader:
        try:
            asn: AsnEntry = AsnEntry(asn=row.get("ASN"))
        except ValidationError as e:
            logger.warning(f"Validation error for ASN row: {e}")
            continue

        org_name = row.get("OrgName", "Unknown").strip()
        info = row.get("Info", "").strip()
        date = row.get("Date", "").strip()

        # Format the source description with all available information
        description = f"LETHAL-FORENSICS ASN Blacklist ({org_name}"
        if info:
            description += f", {info}"
        if date:
            description += f", {date}"
        description += ")"
        asn.name = description
        asn.sources.add(AsnSource.LETHAL_FORENSICS)

        if not asn.asn:
            continue
        result[asn.asn] = asn
    logger.info(f"Loaded {len(result)} ASNs from LETHAL-FORENSICS ASN Blacklist")

    return result


def update_bad_asn_cache() -> bool:
    """
    Download all bad ASN lists and merge them into a single cache file.
    Only updates if cache is older than 24 hours or doesn't exist.

    Returns:
        True if cache was updated, False if skipped (cache is fresh)
    """
    # Check if cache exists and is fresh
    if CACHE_FILE.exists():
        file_age = time.time() - CACHE_FILE.stat().st_mtime
        if file_age < CACHE_MAX_AGE:
            logger.info(
                f"Bad ASN cache is fresh (age: {file_age / 3600:.1f} hours), skipping update"
            )
            return False

    logger.info("Updating Bad ASN cache...")

    # Ensure data directory exists
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Download both sources
    merged_data = {}

    # Spamhaus ASNDROP (priority: has country codes)
    spamhaus_data = download_spamhaus_asndrop()
    merged_data.update(spamhaus_data)

    # Brianhama Bad ASN List (merge intelligently, don't overwrite)
    brianhama_data = download_brianhama_bad_asn()
    for asn, entry in brianhama_data.items():
        if asn in merged_data:
            merged_data[asn] = merged_data[asn] + entry
        else:
            merged_data[asn] = entry

    # LETHAL-FORENSICS ASN Blacklist (merge intelligently, don't overwrite)
    lethal_forensics_data = download_lethal_forensics_asn()
    for asn, entry in lethal_forensics_data.items():
        if asn in merged_data:
            merged_data[asn] = merged_data[asn] + entry
        else:
            merged_data[asn] = entry

    # Save to cache
    serialized_asns = {asn: entry.model_dump(mode="json") for asn, entry in merged_data.items()}
    cache_data = {"last_updated": time.time(), "asns": serialized_asns}

    try:
        CACHE_FILE.write_bytes(orjson.dumps(cache_data, option=orjson.OPT_INDENT_2))
        logger.info(f"Bad ASN cache updated successfully with {len(merged_data)} ASNs")
        return True
    except Exception as e:
        logger.error(f"Failed to save Bad ASN cache: {e}")
        return False


def load_bad_asn_cache() -> dict[str, AsnEntry]:
    """
    Load the bad ASN cache from disk.

    Returns:
        Dictionary mapping ASN (string) to AsnEntry
    """
    if not CACHE_FILE.exists():
        logger.warning("Bad ASN cache file not found, returning empty cache")
        return {}

    try:
        cache_data = orjson.loads(CACHE_FILE.read_bytes())
        raw_asns: dict = cache_data.get("asns", {})
        result = {}
        for asn, entry_data in raw_asns.items():
            try:
                result[asn] = AsnEntry.model_validate(entry_data)
            except ValidationError as e:
                logger.warning(f"Failed to deserialize ASN {asn} from cache: {e}")
        return result
    except Exception as e:
        logger.error(f"Failed to load Bad ASN cache: {e}")
        return {}


def check_asn(asn_value: str | int) -> AsnEntry | None:
    """
    Check if an ASN is in the bad ASN cache.

    Args:
        asn_value: ASN to check (string or integer)

    Returns:
        AsnEntry if ASN is listed, None otherwise
    """
    asn: str = normalize_asn(asn_value)
    cache: dict[str, AsnEntry] = load_bad_asn_cache()
    return cache.get(asn)


def background_updater():
    """
    Background thread function that periodically updates the bad ASN cache.
    Updates once every 24 hours.
    """
    logger.info("Bad ASN background updater started")

    # Initial update on startup
    update_bad_asn_cache()

    # Periodic updates
    while True:
        time.sleep(CACHE_MAX_AGE)  # Sleep for 24 hours
        update_bad_asn_cache()
