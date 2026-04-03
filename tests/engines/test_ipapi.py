import logging

import pytest
import responses

from engines.ipapi import IPAPIEngine
from models.ipapi import IpapiAsn, IpapiLocation, IpapiReport, IpapiVpn
from models.observable import Observable, ObservableType
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
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable():
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


# ============================================================================
# High Priority: Success Tests & Credentials
# ============================================================================


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable.value,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
        "asn": {"asn": "15169", "org": "Google LLC"},
        "vpn": {"service": "TestVPN", "url": "https://testvpn.example"},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.ip == ipv4_observable.value
    assert result.asn.asn == "AS15169"


@responses.activate
def test_analyze_minimal_and_asn_missing(secrets_without_key, ipv4_observable):
    engine = IPAPIEngine(secrets_without_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"ip": ipv4_observable.value}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.asn.asn == "Unknown"


@responses.activate
def test_analyze_missing_credentials_error(secrets_with_key, ipv4_observable):
    """Test handling of API response indicating missing/invalid credentials."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"error": "invalid API key"}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    # When 'ip' key is missing from response, analyze returns an error report
    assert result.success is False


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert "IPAPI request failed" in caplog.text


@responses.activate
def test_create_export_row_full():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = IpapiReport(
        ip="1.1.1.1",
        is_vpn=True,
        is_tor=False,
        is_proxy=False,
        is_abuser=False,
        location=IpapiLocation(city="LA", state="CA", country="United States", country_code="US"),
        asn=IpapiAsn(asn="AS15169", org="Google LLC"),
        vpn=IpapiVpn(service="TestVPN", url="https://testvpn.example"),
    )

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_city"] == "LA"


def test_create_export_row_none():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)

    assert all(v is None for v in row.values())


# ============================================================================
# Medium Priority: Other Critical Paths Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(secrets_with_key, ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv6_observable.value,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {
            "city": "Mountain View",
            "state": "CA",
            "country": "United States",
            "country_code": "US",
        },
        "asn": {"asn": "15169", "org": "Google LLC"},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable)

    assert result.success is True
    assert result.ip == ipv6_observable.value
    assert result.asn.asn == "AS15169"


@responses.activate
def test_analyze_asn_without_asn_subfield(secrets_with_key, ipv4_observable):
    """Test handling of ASN dict without 'asn' subfield."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable.value,
        "asn": {"org": "Google LLC"},  # Missing 'asn' subfield
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.ip == ipv4_observable.value


@responses.activate
def test_analyze_asn_with_empty_asn_value(secrets_with_key, ipv4_observable):
    """Test handling of ASN dict that is falsy (e.g., empty)."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable.value,
        "asn": {},  # Empty dict is falsy
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    # Empty asn dict triggers default
    assert result.asn.asn == "Unknown"


@responses.activate
def test_analyze_response_missing_ip_key(secrets_with_key, ipv4_observable, caplog):
    """Test handling of valid 200 response missing 'ip' key."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"asn": {"asn": "15169", "org": "Google LLC"}}  # Missing 'ip' key

    responses.add(responses.GET, url, json=mock_resp, status=200)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert "missing 'ip' key" in caplog.text


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    import requests as req

    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    timeout_error = req.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert "IPAPI request failed" in caplog.text


@responses.activate
def test_analyze_request_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    import requests as req

    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    conn_error = req.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert "IPAPI request failed" in caplog.text


# ============================================================================
# Low Priority: Edge Cases Tests
# ============================================================================


def test_create_export_row_missing_nested_keys():
    """Test export row when sub-models have missing (default) fields."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = IpapiReport(
        ip="1.1.1.1",
        is_vpn=False,
        location=IpapiLocation(city="LA"),  # state, country, country_code default to ""
        asn=IpapiAsn(asn="AS15169"),  # org defaults to ""
    )

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] == "LA"
    assert row["ipapi_state"] is None
    assert row["ipapi_country"] is None
    assert row["ipapi_country_code"] is None
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_org"] is None


def test_create_export_row_missing_location_dict():
    """Test export row when location fields use defaults."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = IpapiReport(
        ip="1.1.1.1",
        is_vpn=False,
        asn=IpapiAsn(asn="AS15169", org="Google LLC"),
    )

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] is None
    assert row["ipapi_state"] is None
    assert row["ipapi_country"] is None
    assert row["ipapi_country_code"] is None
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_org"] == "Google LLC"


def test_create_export_row_missing_asn_dict():
    """Test export row when ASN fields use defaults (Unknown asn → None in export)."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = IpapiReport(
        ip="1.1.1.1",
        is_vpn=False,
        location=IpapiLocation(city="LA", state="CA", country="United States", country_code="US"),
    )

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] == "LA"
    assert row["ipapi_asn"] is None  # "Unknown" maps to None in export
    assert row["ipapi_org"] is None


def test_create_export_row_default_report():
    """Test export row with a default IpapiReport (all fields at their defaults)."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(IpapiReport())

    assert row["ipapi_ip"] is None
    assert row["ipapi_is_vpn"] is False
    assert row["ipapi_asn"] is None
    assert row["ipapi_org"] is None
    assert row["ipapi_city"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "ipapi"
    assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
