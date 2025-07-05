import logging
from typing import Any

import requests

from utils.utils import identify_observable_type

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "URL",
]

NAME: str = "google_dns"
LABEL: str = "Google common DNS records"
SUPPORTS: list[str] = ["IP", "domain", "URL"]
DESCRIPTION: str = "Checks Google common DNS records (A, AAAA, CNAME, NS, MX, TXT, PTR) for IP, domain, URL"
COST: str = "Free"
API_KEY_REQUIRED: bool = False

# List of DNS record types and their identifiers (filtered for cybersecurity relevance)
DNS_RECORD_TYPES = [
    {"type": "A", "id": 1},  # IPv4 address
    {"type": "AAAA", "id": 28},  # IPv6 address
    {"type": "CNAME", "id": 5},  # Canonical name
    {"type": "MX", "id": 15},  # Mail exchange
    {"type": "TXT", "id": 16},  # Text records (e.g., SPF, DKIM)
    {"type": "PTR", "id": 12},  # Reverse DNS
    {"type": "NS", "id": 2},  # Name server
    {"type": "SOA", "id": 6},  # Start of Authority
    # "SPF" and "DMARC" are logical types, not DNS types, so not included here
]


def extract_domain(observable: str) -> str:
    if "://" in observable:
        domain = observable.split("/")[2]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain
    return observable


def parse_spf_record(txt: str) -> dict:
    fields = {}
    for part in txt.split():
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
        else:
            fields.setdefault("mechanisms", []).append(part)
    return fields


def parse_dmarc_record(txt: str) -> dict:
    fields = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def query_dmarc(
    observable: str,
    observable_type: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """Queries Google DNS for DMARC records of the given observable."""

    try:
        domain = extract_domain(observable)
        dmarc_domain = f"_dmarc.{domain}"
        url = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()

        for answer in data.get("Answer", []):
            txt = answer.get("data", "").replace('"', "").replace("; ", ";")
            if txt.strip().lower().startswith("v=dmarc1"):
                return {
                    "type_name": "DMARC",
                    "domain": domain,
                    "present": True,
                    "data": txt,
                    "parsed": parse_dmarc_record(txt),
                }
        return {
            "type_name": "DMARC",
            "domain": domain,
            "present": False,
            "data": None,
            "parsed": None,
            "message": "No DMARC record found.",
        }
    except Exception as e:
        logger.error("Error querying DMARC for '%s' (%s): %s", observable, observable_type, e, exc_info=True)
        return None


def query_spf(
    observable: str,
    observable_type: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """Queries Google DNS for SPF records of the given observable."""

    domain: str = extract_domain(observable)
    url: str = f"https://dns.google/resolve?name={domain}&type=TXT"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying Google DNS for SPF record of {observable}: {e}", exc_info=True)
        return None

    try:
        for answer in data.get("Answer", []):
            txt = answer.get("data", "").replace('"', "")
            if txt.strip().lower().startswith("v=spf"):
                return {
                    "type_name": "SPF",
                    "domain": domain,
                    "present": True,
                    "data": txt,
                    "parsed": parse_spf_record(txt),
                }
        return {
            "type_name": "SPF",
            "domain": domain,
            "present": False,
            "data": None,
            "parsed": None,
            "message": "No SPF record found.",
        }
    except Exception as e:
        logger.error("Error querying SPF for '%s' (%s): %s", observable, observable_type, e, exc_info=True)
        return None


def reverse_dns_lookup(
    observable: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """Performs a reverse DNS lookup for the given observable (IP address)."""

    reverse_name = f"{observable}.in-addr.arpa" if ":" not in observable else f"{observable}.ip6.arpa"
    url = f"https://dns.google/resolve?name={reverse_name}&type=PTR"

    try:
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error("Error querying Google DNS for reverse lookup of '%s': %s", observable, e, exc_info=True)
        return None

    for answer in data.get("Answer", []):
        answer["type_name"] = next(
            (record["type"] for record in DNS_RECORD_TYPES if record["id"] == answer["type"]), "Unknown"
        )
    return data


def forward_dns_lookup(
    observable: str, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, Any] | None:
    """Query Google DNS for common records of the given observable (FQDN)."""

    all_records: list[dict] = []

    for record in DNS_RECORD_TYPES:
        url = f"https://dns.google/resolve?name={observable}&type={record['id']}"

        try:
            response = requests.get(url, proxies=proxies, verify=ssl_verify)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            logger.error("Error querying Google DNS for '%s' (%s): %s", observable, record["type"], e, exc_info=True)
            continue

        for answer in data.get("Answer", []):
            try:
                answer["type_name"] = record["type"]
                # ignore the TXT entry that contains SPF - it will be handled separately
                if answer["type_name"] == "TXT" and "spf" in answer["data"].lower():
                    continue
                # remove trailing "." from all data answers
                answer["data"] = answer["data"].rstrip(".")
                if answer["type_name"] == "MX":
                    answer["data"] = answer["data"].strip().split(" ")[-1]
                all_records.append(answer)
            except KeyError as e:
                logger.error(
                    "KeyError while processing DNS answer for '%s' (%s): %s",
                    observable,
                    record["type"],
                    e,
                    exc_info=True,
                )
                continue

    # Parse TXT records for SPF
    spf_result = query_spf(observable, "FQDN", proxies, ssl_verify)
    dmarc_result = query_dmarc(observable, "FQDN", proxies, ssl_verify)

    if spf_result:
        all_records.append(spf_result)
    if dmarc_result:
        all_records.append(dmarc_result)

    return {"Answer": all_records}


def url_lookups(
    observable: str, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, Any] | None:
    extracted = observable.split("/")[2]

    if ":" in extracted:
        extracted = extracted.split(":")[0]

    extracted_type: str = identify_observable_type(extracted)
    spf_result: dict | None = query_spf(observable, "URL", proxies, ssl_verify)
    dmarc_result: dict | None = query_dmarc(observable, "URL", proxies, ssl_verify)

    # re-run lookups for the extracted domain
    dns_result: dict | None = run_engine(extracted, extracted_type, proxies, ssl_verify)

    if not dns_result:
        dns_result = {"Answer": []}
    if spf_result:
        dns_result["Answer"].append(spf_result)
    if dmarc_result:
        dns_result["Answer"].append(dmarc_result)

    return dns_result


def run_engine(
    observable: str, observable_type: str, proxies: dict[str, str] | None = None, ssl_verify: bool = True
) -> dict[str, Any] | None:
    if observable_type in ["IPv4", "IPv6"]:
        return reverse_dns_lookup(observable, proxies, ssl_verify)

    if observable_type == "FQDN":
        return forward_dns_lookup(observable, proxies, ssl_verify)

    if observable_type == "URL":
        return url_lookups(observable, proxies, ssl_verify)

    return None
