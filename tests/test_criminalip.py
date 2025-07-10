import responses
from typing import Any

import pytest
from pytest_mock import mocker
from requests.exceptions import RequestException

from engines.criminalip import (
    SuspiciousInfoReport,
    query_criminalip,
    run_engine,
)
from utils.config import Secrets


@pytest.fixture
def mock_data():
    return {
        "abuse_record_count": 5,
        "current_opened_port": {
            "count": 2,
            "data": [
                {
                    "port": 80,
                    "is_vulnerability": False,
                    "product_name": "nginx",
                    "protocol": "tcp",
                },
                {
                    "port": 443,
                    "is_vulnerability": False,
                    "product_name": "nginx",
                    "protocol": "tcp",
                },
            ],
        },
        "ids": {
            "count": 1,
            "data": [
                {
                    "classification": "malware",
                    "message": "Suspicious activity",
                    "source_system": "IDS",
                }
            ],
        },
        "ip": "1.1.1.1",
        "issues": {
            "is_anonymous_vpn": False,
            "is_cloud": True,
            "is_darkweb": False,
            "is_hosting": False,
            "is_mobile": False,
            "is_proxy": False,
            "is_scanner": False,
            "is_snort": False,
            "is_tor": False,
            "is_vpn": False,
        },
        "representative_domain": "example.com",
        "score": {"inbound": "safe", "outbound": "critical"},
        "status": 200,
        "whois": {
            "count": 1,
            "data": [{"as_name": "TEST-AS", "city": "Test City", "org_name": "Test Org"}],
        },
    }


@responses.activate
def test_successful_suspicious_info_retrieval(mock_data: dict[str, Any]) -> None:
    responses.add(
        responses.GET,
        url="https://api.criminalip.io/v2/feature/ip/suspicious-info",
        json=mock_data,
        status=200,
    )

    query_result: dict = query_criminalip(api_key="test_api_key", ip="1.1.1.1", ssl_verify=False)

    assert query_result == mock_data


def test_missing_api_key_handling(mocker):
    mock_secrets: Secrets = Secrets(criminalip_api_key="")
    mocker.patch.object("utils.config.get_config", return_value=mock_secrets)

    api_key: str | None = retrieve_api_key()

    assert api_key is None


@responses.activate
def test_http_error_handling():
    responses.add(
        responses.GET,
        url="https://api.criminalip.io/v2/feature/ip/suspicious-info",
        body=RequestException("API Error"),
        status=500,
    )

    observable: dict = {"value": "1.1.1.1"}
    result = run_engine(observable, None, True)
    assert result is None
