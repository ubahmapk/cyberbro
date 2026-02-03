import logging
from engines.ipapi import IPAPIEngine

import responses
import pytest


from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.ipapi = "K" * 20
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.ipapi = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
        "asn": {"asn": "15169", "org": "Google LLC"},
        "vpn": {"service": "TestVPN", "url": "https://testvpn.example"},
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["asn"]["asn"] == "AS15169"


@responses.activate
def test_analyze_minimal_and_asn_missing(secrets_without_key, ipv4_observable):
    engine = IPAPIEngine(secrets_without_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"ip": ipv4_observable}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"]["asn"] == "Unknown"


@responses.activate
def test_analyze_http_error(secrets_with_key, ipv4_observable, caplog):
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    responses.add(responses.POST, url, json={"error": "bad"}, status=500)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipapi" in caplog.text


@responses.activate
def test_create_export_row_full():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "is_vpn": True,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
        "asn": {"asn": "AS15169", "org": "Google LLC"},
        "vpn": {"service": "TestVPN", "url": "https://testvpn.example"},
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_city"] == "LA"


def test_create_export_row_none():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)

    assert all(v is None for v in row.values())
