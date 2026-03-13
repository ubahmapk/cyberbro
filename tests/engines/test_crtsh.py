import logging
from unittest.mock import patch

import pytest
import requests
import responses

from engines.crtsh import CrtShEngine
from models.crtsh import CrtShReport, DomainCount
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

CRTSH_JSON_URL = "https://crt.sh/json"


@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def url_observable_with_port():
    return Observable(value="https://example.com:8443/api/path", type=ObservableType.URL)


@pytest.fixture
def url_observable_without_port():
    return Observable(value="https://subdomain.example.com/some/path", type=ObservableType.URL)


@pytest.fixture
def subdomain_observable():
    return Observable(value="www.example.com", type=ObservableType.FQDN)


# ============================================================================
# High Priority: Critical Paths - FQDN/URL Analysis
# ============================================================================


@responses.activate
def test_analyze_fqdn_success_single_domain(fqdn_observable):
    """Test successful analysis of FQDN with single domain."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [{"common_name": "example.com"}]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result.success is True
    assert len(result.top_domains) == 1
    assert result.top_domains[0].domain == "example.com"
    assert result.top_domains[0].count == 1
    assert result.link == f"https://crt.sh/?q={fqdn_observable.value}"


@responses.activate
def test_analyze_fqdn_success_multiple_domains(fqdn_observable):
    """Test successful analysis with multiple certificate records and domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com",
        },
        {
            "common_name": "www.example.com",
            "name_value": "www.example.com\nmail.example.com",
        },
        {
            "common_name": "api.example.com",
        },
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result.success is True
    top_domains = result.top_domains
    # Domain counts: api.example.com(2), www.example.com(2),
    # example.com(1), mail.example.com(1) - sorted by count desc
    assert len(top_domains) == 4
    counts = [d.count for d in top_domains]
    assert counts[0] == 2
    assert counts[1] == 2
    assert counts[2] == 1
    assert counts[3] == 1


@responses.activate
def test_analyze_url_success_with_port(url_observable_with_port):
    """Test successful analysis of URL with port number."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
        }
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(url_observable_with_port)

    assert result is not None
    assert len(result.top_domains) == 2
    domain_names = {d.domain for d in result.top_domains}
    assert domain_names == {"example.com", "www.example.com"}


@responses.activate
def test_analyze_url_success_without_port(url_observable_without_port):
    """Test successful analysis of URL without port number."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    extracted_domain = "subdomain.example.com"

    mock_resp = [
        {
            "common_name": "subdomain.example.com",
            "name_value": "subdomain.example.com\napi.subdomain.example.com",
        }
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(url_observable_without_port)

    assert result is not None
    assert len(result.top_domains) == 2
    assert result.link == f"https://crt.sh/?q={extracted_domain}"


@responses.activate
def test_analyze_empty_certificate_list(fqdn_observable):
    """Test analysis when domain has no certificates."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    responses.add(responses.GET, CRTSH_JSON_URL, json=[], status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result.top_domains == []
    assert result.link == f"https://crt.sh/?q={fqdn_observable.value}"


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_analyze_http_error_codes(fqdn_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 404, 500)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    responses.add(responses.GET, CRTSH_JSON_URL, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result.success is False
    assert "Error querying crt.sh" in caplog.text


@responses.activate
@patch("time.sleep")
def test_analyze_connection_error(mock_sleep, fqdn_observable, caplog):
    """Test handling of connection timeout."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, CRTSH_JSON_URL, body=timeout_error)

    caplog.set_level(logging.INFO)
    result = engine.analyze(fqdn_observable)

    assert result.success is False
    assert "Timeout occurred while querying crt.sh" in caplog.text


# ============================================================================
# Medium Priority: Response Edge Cases
# ============================================================================


@responses.activate
def test_analyze_name_value_with_multiple_names(fqdn_observable):
    """Test parsing of name_value with multiple newline-separated domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    name_value = "example.com\nwww.example.com\napi.example.com\nmail.example.com\ncdn.example.com"
    mock_resp = [{"common_name": "example.com", "name_value": name_value}]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result.top_domains) == 5
    for domain in result.top_domains:
        assert domain.count == 1


@responses.activate
def test_analyze_common_name_only(fqdn_observable):
    """Test handling of records with only common_name (no name_value)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [
        {"common_name": "example.com"},
        {"common_name": "example.com"},
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result.top_domains) == 1
    assert result.top_domains[0].domain == "example.com"
    assert result.top_domains[0].count == 2


@responses.activate
def test_analyze_name_value_only(fqdn_observable):
    """Test handling of records where name_value contains all domains (common_name overlaps)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [
        {
            "common_name": "www.example.com",
            "name_value": "www.example.com\napi.example.com",
        },
        {
            "common_name": "mail.example.com",
            "name_value": "mail.example.com",
        },
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result.top_domains) == 3
    domain_names = {d.domain for d in result.top_domains}
    assert domain_names == {"www.example.com", "api.example.com", "mail.example.com"}


@responses.activate
def test_analyze_name_value_with_empty_lines(fqdn_observable):
    """Test handling of name_value with empty lines and whitespace."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\n\nwww.example.com\napi.example.com\n",
        }
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    # name_value splits on \n; empty strings from blank/trailing lines become "" domain entries
    domain_names = {d.domain for d in result.top_domains}
    assert {"example.com", "www.example.com", "api.example.com"}.issubset(domain_names)


@responses.activate
def test_analyze_invalid_json_response(fqdn_observable, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    responses.add(responses.GET, CRTSH_JSON_URL, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result.success is False
    assert "Unexpected error while parsing" in caplog.text


# ============================================================================
# Low Priority: Export Row Formatting & Edge Cases
# ============================================================================


def test_create_export_row_with_domains():
    """Test export row formatting with populated top_domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = CrtShReport(
        success=True,
        top_domains=[
            DomainCount(domain="example.com", count=5),
            DomainCount(domain="www.example.com", count=3),
            DomainCount(domain="api.example.com", count=2),
        ],
        link="https://crt.sh/?q=example.com",
    )

    row = engine.create_export_row(analysis_result)

    assert row["crtsh_top_domains"] == "example.com, www.example.com, api.example.com"


def test_create_export_row_with_none():
    """Test export row with None analysis result."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["crtsh_top_domains"] is None


@responses.activate
def test_analyze_domain_count_sorting():
    """Test that domains are correctly sorted by count."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    observable = Observable(value="example.com", type=ObservableType.FQDN)

    mock_resp = [
        {"common_name": "a.example.com"},
        {"common_name": "a.example.com"},
        {"common_name": "a.example.com"},
        {"common_name": "a.example.com"},
        {"common_name": "a.example.com"},
        {"common_name": "b.example.com"},
        {"common_name": "b.example.com"},
        {"common_name": "b.example.com"},
        {"common_name": "c.example.com"},
        {"common_name": "c.example.com"},
    ]
    responses.add(responses.GET, CRTSH_JSON_URL, json=mock_resp, status=200)

    result = engine.analyze(observable)

    assert result is not None
    top_domains = result.top_domains
    assert len(top_domains) == 3
    assert top_domains[0].domain == "a.example.com"
    assert top_domains[0].count == 5
    assert top_domains[1].domain == "b.example.com"
    assert top_domains[1].count == 3
    assert top_domains[2].domain == "c.example.com"
    assert top_domains[2].count == 2


def test_create_export_row_empty_domains():
    """Test export row with empty top_domains list."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = CrtShReport(
        success=True,
        top_domains=[],
        link="https://crt.sh/?q=example.com",
    )

    row = engine.create_export_row(analysis_result)

    assert row["crtsh_top_domains"] is None


# ============================================================================
# New Tests: Success/failure flags and invalid URL
# ============================================================================


@responses.activate
def test_analyze_success_sets_success_flag(fqdn_observable):
    """Test that result.success is True on a normal successful response."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    responses.add(responses.GET, CRTSH_JSON_URL, json=[{"common_name": "example.com"}], status=200)

    result = engine.analyze(fqdn_observable)

    assert result.success is True


@responses.activate
def test_analyze_error_sets_error_message(fqdn_observable, caplog):
    """Test that result.error is a non-empty string when the engine returns a failure report."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    responses.add(responses.GET, CRTSH_JSON_URL, json={"error": "error"}, status=500)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result.success is False
    assert result.error
    assert len(result.error) > 0


def test_analyze_invalid_url_returns_failure():
    """Test that an unresolvable URL observable returns a failure report."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    observable = Observable(value="not-a-valid-url", type=ObservableType.URL)

    result = engine.analyze(observable)

    assert result.success is False


# ============================================================================
# Properties Tests
# ============================================================================


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "crtsh"
    assert engine.supported_types is ObservableType.FQDN | ObservableType.URL
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False
