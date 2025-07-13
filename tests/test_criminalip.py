from curses.ascii import SP
import responses
from typing import Any
from models.datatypes import Proxies, ObservableMap, Report

import pytest
from pytest_mock import mocker
from requests.exceptions import RequestException
from utils.config import QueryError

from engines.criminalip import (
    SuspiciousInfoReport,
    query_criminalip,
    parse_criminalip_response,
    run_engine,
)
from utils.config import Secrets

ip: str = "196.188.187.85"


@pytest.fixture()
def valid_query_response() -> dict:
    query_result: dict = {
        "status": 200,
        "ip": "196.188.187.85",
        "score": {"inbound": "Critical", "outbound": "Critical"},
        "issues": {
            "is_vpn": False,
            "is_cloud": False,
            "is_tor": False,
            "is_proxy": False,
            "is_hosting": False,
            "is_mobile": False,
            "is_darkweb": False,
            "is_scanner": True,
            "is_snort": False,
        },
        "representative_domain": "",
        "abuse_record_count": 2,
        "whois": {
            "count": 1,
            "data": [
                {
                    "as_name": "Ethiopian Telecommunication Corporation",
                    "as_no": 24757,
                    "city": "Addis Ababa",
                    "region": "Addis Ababa",
                    "org_name": "Ethiopian Telecommunication Corporation",
                    "postal_code": None,
                    "latitude": 9.0245,
                    "longitude": 38.7485,
                    "org_country_code": "et",
                    "confirmed_time": "2025-07-13 00:00:00",
                }
            ],
        },
        "ids": {"count": 0, "data": []},
        "current_opened_port": {
            "count": 4,
            "data": [
                {
                    "port": 22,
                    "socket_type": "tcp",
                    "protocol": "SSH",
                    "product_name": "OpenSSH",
                    "product_version": "8.9p1",
                    "tags": [],
                    "is_vulnerability": True,
                    "confirmed_time": "2025-07-09 18:02:29",
                },
                {
                    "port": 8080,
                    "socket_type": "tcp",
                    "protocol": "HTTP",
                    "product_name": "httpd",
                    "product_version": "Unknown",
                    "tags": [],
                    "is_vulnerability": False,
                    "confirmed_time": "2025-07-07 22:46:09",
                },
                {
                    "port": 80,
                    "socket_type": "tcp",
                    "protocol": "HTTP",
                    "product_name": "nginx",
                    "product_version": "1.18.0",
                    "tags": ["DevOps"],
                    "is_vulnerability": True,
                    "confirmed_time": "2025-07-07 06:21:51",
                },
                {
                    "port": 4000,
                    "socket_type": "tcp",
                    "protocol": "",
                    "product_name": "httpd",
                    "product_version": "Unknown",
                    "tags": [],
                    "is_vulnerability": False,
                    "confirmed_time": "2025-07-01 03:24:19",
                },
            ],
        },
    }

    return query_result


@pytest.fixture()
def query_response_missing_status(valid_query_response):
    response: dict = valid_query_response.copy()
    response.pop("status")

    return response


@pytest.fixture()
def valid_suspiciousinfo_report(valid_query_response) -> SuspiciousInfoReport:
    return SuspiciousInfoReport(**valid_query_response)


@responses.activate
def test_successful_suspicious_info_retrieval(valid_query_response: dict[str, Any], api_key, proxies) -> None:
    responses.add(
        responses.GET,
        url="https://api.criminalip.io/v2/feature/ip/suspicious-info",
        json=valid_query_response,
        status=200,
    )

    query_result: dict = query_criminalip(api_key, ip="196.188.187.85", proxies=proxies, ssl_verify=False)

    assert query_result == valid_query_response


@responses.activate
def test_http_error_handling(ip_observable_dict, proxies):
    responses.add(
        responses.GET,
        url="https://api.criminalip.io/v2/feature/ip/suspicious-info",
        body=RequestException("API Error"),
        status=500,
    )

    result = run_engine(ip_observable_dict, proxies=proxies, ssl_verify=True)
    assert result is None


def test_parse_criminalip_response(valid_suspiciousinfo_report, valid_query_response):
    report: SuspiciousInfoReport = parse_criminalip_response(valid_query_response)

    assert report == valid_suspiciousinfo_report


def test_parse_criminalip_response_malformed_response(query_response_missing_status):
    with pytest.raises(QueryError):
        _ = parse_criminalip_response(query_response_missing_status)
