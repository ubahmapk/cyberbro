import logging
from unittest.mock import patch

import pytest

from engines.abusix import AbusixEngine
from models.abusix import AbusixReport
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_config():
    return Secrets()


@pytest.fixture
def ipv4_observable():
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable():
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


# High Priority Tests: Credentials/Auth Error Handling


@patch("querycontacts.ContactFinder")
def test_analyze_exception_generic(
    mock_contact_finder, secrets_with_config, ipv4_observable, caplog
):
    """Test handling of generic exceptions (network, service errors)."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.side_effect = Exception("Connection timeout")

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert result.error is not None
    assert "Connection timeout" in caplog.text
    mock_instance.find.assert_called_once_with(ipv4_observable.value)


# Medium Priority Tests: Critical Paths


@pytest.mark.parametrize(
    "observable,expected_email",
    [
        (Observable(value="1.1.1.1", type=ObservableType.IPV4), "abuse@example.com"),
        (
            Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6),
            "abuse-ipv6@example.com",
        ),
    ],
)
@patch("querycontacts.ContactFinder")
def test_analyze_success(mock_contact_finder, secrets_with_config, observable, expected_email):
    """Test successful analysis of IPv4 and IPv6 addresses."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = [expected_email]

    result = engine.analyze(observable)

    assert result.success is True
    assert result.abuse_email == expected_email
    mock_instance.find.assert_called_once_with(observable.value)


@patch("querycontacts.ContactFinder")
def test_analyze_empty_results(mock_contact_finder, secrets_with_config, ipv4_observable):
    """Test handling of empty results from querycontacts."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = []

    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert result.error is not None
    mock_instance.find.assert_called_once_with(ipv4_observable.value)


@patch("querycontacts.ContactFinder")
def test_analyze_multiple_results_uses_first(
    mock_contact_finder, secrets_with_config, ipv4_observable
):
    """Test that only first result is used when multiple are returned."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = [
        "abuse1@example.com",
        "abuse2@example.com",
    ]

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.abuse_email == "abuse1@example.com"
    mock_instance.find.assert_called_once_with(ipv4_observable.value)


# Low Priority Tests: Edge Cases and Properties


def test_create_export_row_with_result(secrets_with_config):
    """Test export row creation with valid analysis result."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    analysis_result = AbusixReport(success=True, abuse_email="abuse@example.com")

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"abusix_abuse": "abuse@example.com"}


def test_create_export_row_with_none(secrets_with_config):
    """Test export row creation with None result."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row == {"abusix_abuse": None}


def test_create_export_row_with_failed_report(secrets_with_config):
    """Test that a failed report (success=False) still surfaces the email field."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    analysis_result = AbusixReport(success=False, error="some error")

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"abusix_abuse": None}


def test_name_property(secrets_with_config):
    """Test that name property returns correct engine identifier."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)

    assert engine.name == "abusix"


def test_supported_types_property(secrets_with_config):
    """Test that supported_types includes both IPv4 and IPv6."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)

    assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6


def test_execute_after_reverse_dns_property(secrets_with_config):
    """Test that execute_after_reverse_dns returns True (post-pivot engine)."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)

    assert engine.execute_after_reverse_dns is True


def test_is_pivot_engine_property(secrets_with_config):
    """Test that is_pivot_engine returns False (inherited default)."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)

    assert engine.is_pivot_engine is False
