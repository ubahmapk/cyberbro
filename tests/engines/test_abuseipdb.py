import logging
from unittest.mock import patch

import pytest
import requests
import responses

from engines.abuseipdb import AbuseIPDBEngine
from models.abuseipdb import AbuseIPDBReport
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.abuseipdb = "test_api_key_value"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.abuseipdb = ""
    return s


@pytest.fixture
def ipv4_observable():
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable():
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


# ============================================================================
# High Priority: Rewritten + Credentials Tests
# ============================================================================


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    """Test successful API response with all data fields."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {
        "data": {
            "ipAddress": ipv4_observable.value,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 25,
            "countryCode": "AU",
            "usageType": "Content Delivery Network",
            "isp": "APNIC and Cloudflare DNS Resolver project",
            "domain": "cloudflare.com",
            "hostnames": ["one.one.one.one"],
            "isTor": False,
            "totalReports": 24,
            "numDistinctUsers": 8,
            "lastReportedAt": "2025-04-22T13:01:09+00:00",
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is True
    assert result.reports == 24
    assert result.risk_score == 25
    assert result.link == f"https://www.abuseipdb.com/check/{ipv4_observable.value}"
    assert result.is_whitelisted is True
    assert result.country_code == "AU"
    assert result.country_name == "Australia"
    assert result.isp == "APNIC and Cloudflare DNS Resolver project"
    assert result.domain == "cloudflare.com"
    assert result.is_tor is False
    assert result.last_reported_at == "2025-04-22T13:01:09+00:00"


def test_analyze_no_api_key(secrets_without_key, ipv4_observable, caplog):
    """Test that missing API key returns a failed report."""
    engine = AbuseIPDBEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API key not set" in caplog.text


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_returns_failed_report(
    secrets_with_key, ipv4_observable, status_code, caplog
):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API error" in caplog.text


@responses.activate
def test_analyze_response_missing_data_key(secrets_with_key, ipv4_observable, caplog):
    """Test handling of valid 200 response missing 'data' key returns failed report."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {"error": "No data"}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API response parsing error" in caplog.text


# ============================================================================
# Medium Priority: Critical Paths Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(secrets_with_key, ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {
        "data": {
            "ipAddress": ipv6_observable.value,
            "abuseConfidenceScore": 50,
            "totalReports": 5,
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable)

    assert result is not None
    assert result.success is True
    assert result.reports == 5
    assert result.risk_score == 50
    assert result.link == f"https://www.abuseipdb.com/check/{ipv6_observable.value}"


@responses.activate
@patch("time.sleep")
def test_analyze_request_timeout_returns_failed_report(
    mock_sleep, secrets_with_key, ipv4_observable, caplog
):
    """Test handling of request timeout returns failed report."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API error" in caplog.text


@responses.activate
@patch("time.sleep")
def test_analyze_connection_error_returns_failed_report(
    mock_sleep, secrets_with_key, ipv4_observable, caplog
):
    """Test handling of connection error returns failed report."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API error" in caplog.text


@responses.activate
def test_analyze_invalid_json_returns_failed_report(secrets_with_key, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON returns failed report."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result.success is False
    assert result.error is not None
    assert "AbuseIPDB API response parsing error" in caplog.text


# ============================================================================
# Low Priority: Export Row & Property Tests
# ============================================================================


def test_create_export_row_with_data():
    """Test export row with non-zero reports and risk_score."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = AbuseIPDBReport(
        ip_address="1.1.1.1",
        risk_score=75,
        reports=42,
        country_code="DE",
        country_name="Germany",
        isp="3xK Tech GmbH",
        domain="3xktech.cloud",
        usage_type="Data Center/Web Hosting/Transit",
        is_tor=False,
        last_reported_at="2026-02-05T21:42:02+00:00",
        success=True,
    )

    row = engine.create_export_row(analysis_result)

    assert row["a_ipdb_reports"] == 42
    assert row["a_ipdb_risk"] == 75
    assert row["a_ipdb_country"] == "Germany"
    assert row["a_ipdb_isp"] == "3xK Tech GmbH"
    assert row["a_ipdb_domain"] == "3xktech.cloud"
    assert row["a_ipdb_usage_type"] == "Data Center/Web Hosting/Transit"
    assert row["a_ipdb_is_tor"] is False
    assert row["a_ipdb_last_reported"] == "2026-02-05T21:42:02+00:00"


def test_create_export_row_none():
    """Test export row with None result."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["a_ipdb_reports"] is None
    assert row["a_ipdb_risk"] is None
    assert row["a_ipdb_country"] is None
    assert row["a_ipdb_isp"] is None
    assert row["a_ipdb_domain"] is None
    assert row["a_ipdb_usage_type"] is None
    assert row["a_ipdb_is_tor"] is None
    assert row["a_ipdb_last_reported"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "abuseipdb"
    assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
