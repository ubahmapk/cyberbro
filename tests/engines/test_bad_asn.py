"""
Tests for Bad ASN Check engine and manager.
"""

import logging

import pytest
from pytest_mock import MockerFixture

from engines.bad_asn import (
    BadASNEngine,
    calculate_risk_score,
    extract_asn_org_name,
    is_legitimate_provider,
)
from models.bad_asn import AsnEntry, AsnSource, BadAsnReport, BadAsnStatus
from models.observable import Observable, ObservableType
from utils.config import Secrets


def _make_asn_entry(
    asn: str, name: str = "", cc: str = "", sources: list | None = None
) -> AsnEntry:
    entry = AsnEntry(asn=asn, name=name, cc=cc)
    for src in sources or []:
        entry.sources.add(src)
    return entry


def test_bad_asn_engine_analyze_with_context(mocker: MockerFixture):
    """Test BadASNEngine.analyze with ASN in context."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"ipquery": {"asn": "401696"}}

    mock_entry = _make_asn_entry("401696", name="Test Source", sources=[AsnSource.SPAMHAUS])
    mocker.patch("engines.bad_asn.check_asn", return_value=mock_entry)

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=context)

    assert result is not None
    assert result.status == BadAsnStatus.MALICIOUS
    assert result.asn == "401696"
    assert result.asn_org_name == "Test Source"
    assert AsnSource.SPAMHAUS in result.sources


def test_bad_asn_engine_analyze_without_context(caplog):
    """Test BadASNEngine.analyze without context logs warning."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=None)

    assert result is not None
    assert result.success is False
    assert "No context provided for" in caplog.text


def test_bad_asn_engine_analyze_no_asn_in_context():
    """Test BadASNEngine.analyze with context but no ASN."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"some_other_engine": {"data": "value"}}

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=context)

    assert result is not None
    assert result.success is False


@pytest.mark.parametrize(
    "context_key,context_value,expected_asn",
    [
        ("ipinfo", {"asn": "AS15169 Google LLC"}, "15169"),
        ("ipapi", {"asn": {"asn": "AS15169", "org": "Google LLC"}}, "15169"),
    ],
)
def test_bad_asn_engine_extract_asn_from_context_sources(context_key, context_value, expected_asn):
    """Test ASN extraction from different context sources."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {context_key: context_value}

    asn = engine._extract_asn_from_context(context)

    assert asn == expected_asn


def test_bad_asn_engine_create_export_row():
    """Test create_export_row method."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    analysis_result = BadAsnReport(
        success=True,
        status=BadAsnStatus.MALICIOUS,
        asn="401696",
        sources={AsnSource.SPAMHAUS},
        details="Test details",
    )

    export_row = engine.create_export_row(analysis_result)

    assert export_row["bad_asn_status"] == BadAsnStatus.MALICIOUS
    assert export_row["bad_asn_asn"] == "401696"
    assert export_row["bad_asn_sources"] == "Spamhaus"
    assert export_row["bad_asn_details"] == "Test details"


def test_bad_asn_engine_create_export_row_none():
    """Test create_export_row with None result."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    export_row = engine.create_export_row(None)

    assert export_row["bad_asn_status"] == "N/A"
    assert export_row["bad_asn_asn"] == ""


# Additional tests for helpers and edge cases


def test_is_legitimate_provider_keyword_variations():
    assert is_legitimate_provider("Amazon Web Services (AWS)") is True
    assert is_legitimate_provider("google cloud platform") is True
    assert is_legitimate_provider("Small Provider LLC") is False
    assert is_legitimate_provider("") is False
    assert is_legitimate_provider(None) is False


def test_calculate_risk_score_all_factors():
    # Both authoritative sources and high-risk country (HK)
    source = "Spamhaus and Brianhama (COGNETCLOUD, cognetcloud.com, HK)"
    score = calculate_risk_score(source, False)
    assert score == 80

    # If legitimate provider, penalty applies
    source2 = "Spamhaus (amazon, example.com, US)"
    score2 = calculate_risk_score(source2, True)
    # Base 50 +10 (spamhaus) -30 (legitimate) = 30
    assert score2 == 30


def test_calculate_risk_score_bounds():
    # Ensure result is always within 0-100 for a variety of inputs
    samples = ["", "random text", "spamhaus", "spamhaus brianhama (RU)"]
    for s in samples:
        score = calculate_risk_score(s, False)
        assert 0 <= score <= 100


@pytest.mark.parametrize(
    "context_key,context_value,expected_org",
    [
        ("ipapi", {"asn": {"asn": "AS1234", "org": "IPAPI Org"}}, "IPAPI Org"),
        ("ipinfo", {"asn": "AS1234 InfoOrg"}, "InfoOrg"),
        ("webscout", {"as_org": "WebScout Org"}, "WebScout Org"),
    ],
)
def test_extract_asn_org_name_from_sources(context_key, context_value, expected_org):
    """Test ASN org name extraction from different sources."""
    context = {context_key: context_value}
    assert extract_asn_org_name(context) == expected_org


def test_extract_asn_priority_order():
    # ipapi should take priority over ipinfo
    context = {
        "ipapi": {"asn": {"asn": "AS1111", "org": "IPAPI Org"}},
        "ipinfo": {"asn": "AS2222 InfoOrg"},
    }
    assert extract_asn_org_name(context) == "IPAPI Org"


def test_extract_asn_ignores_unknown_and_bogon():
    context1 = {"ipinfo": {"asn": "Unknown"}}
    context2 = {"ipinfo": {"asn": "BOGON"}}
    assert extract_asn_org_name(context1) is None
    assert extract_asn_org_name(context2) is None


def test_analyze_legitimate_provider_penalty(mocker: MockerFixture):
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"ipapi": {"asn": {"asn": "AS401696", "org": "Amazon Web Services"}}}

    mock_entry = _make_asn_entry(
        "401696", name="Amazon AWS example.com", cc="US", sources=[AsnSource.SPAMHAUS]
    )
    mocker.patch("engines.bad_asn.check_asn", return_value=mock_entry)

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=context)

    assert result is not None
    assert result.status == BadAsnStatus.POTENTIALLY_LEGITIMATE
    assert result.legitimate_but_abused is True
    assert result.asn_org_name == "Amazon AWS example.com"
    assert result.risk_score == 30
    assert AsnSource.SPAMHAUS in result.sources


def test_analyze_malicious_non_legitimate(mocker: MockerFixture):
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"ipapi": {"asn": {"asn": "AS401696", "org": "Some Org"}}}

    mock_entry = _make_asn_entry(
        "401696", name="COGNETCLOUD", cc="HK", sources=[AsnSource.SPAMHAUS]
    )
    mocker.patch("engines.bad_asn.check_asn", return_value=mock_entry)

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=context)

    assert result is not None
    assert result.status == BadAsnStatus.MALICIOUS
    assert result.legitimate_but_abused is False
    assert result.risk_score == 70
    assert AsnSource.SPAMHAUS in result.sources


def test_analyze_unlisted_asn(mocker: MockerFixture):
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"ipquery": {"asn": "401696"}}

    mocker.patch("engines.bad_asn.check_asn", return_value=None)

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4), context=context)

    assert result is not None
    assert result.status == BadAsnStatus.UNLISTED
    assert result.asn == "401696"


def test_asn_entry_round_trip_serialization():
    """Test that AsnEntry sources are correctly deserialized back to AsnSource members."""
    entry = _make_asn_entry(
        "12345", name="TestOrg", cc="RU", sources=[AsnSource.SPAMHAUS, AsnSource.BRIANHAMA]
    )
    score_before = entry.calculate_risk_score

    data = entry.model_dump(mode="json")
    restored = AsnEntry.model_validate(data)

    assert all(isinstance(s, AsnSource) for s in restored.sources)
    assert AsnSource.SPAMHAUS in restored.sources
    assert AsnSource.BRIANHAMA in restored.sources
    assert restored.calculate_risk_score == score_before


def test_bad_asn_report_round_trip_serialization():
    """Test that BadAsnReport serializes and deserializes correctly."""
    report = BadAsnReport(
        success=True,
        status=BadAsnStatus.MALICIOUS,
        asn="401696",
        sources={AsnSource.SPAMHAUS, AsnSource.BRIANHAMA},
        risk_score=70,
    )

    data = report.model_dump(mode="json")
    assert isinstance(data["sources"], list)
    assert data["status"] == "malicious"
    assert data["__cls__"] == "BadAsnReport"

    restored = BadAsnReport.model_validate(data)
    assert isinstance(restored.sources, set)
    assert all(isinstance(s, AsnSource) for s in restored.sources)
    assert AsnSource.SPAMHAUS in restored.sources
    assert AsnSource.BRIANHAMA in restored.sources
    assert restored.status == BadAsnStatus.MALICIOUS


def test_analyze_ipv6_observable(mocker: MockerFixture):
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    context = {"ipquery": {"asn": "401696"}}

    mock_entry = _make_asn_entry(
        "401696", name="COGNETCLOUD", cc="HK", sources=[AsnSource.SPAMHAUS]
    )
    mocker.patch("engines.bad_asn.check_asn", return_value=mock_entry)

    result = engine.analyze(
        Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6), context=context
    )

    assert result is not None
    assert result.status in (
        BadAsnStatus.MALICIOUS,
        BadAsnStatus.POTENTIALLY_LEGITIMATE,
        BadAsnStatus.UNLISTED,
    )
