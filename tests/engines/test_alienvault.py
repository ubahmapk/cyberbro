from unittest.mock import patch

from models.observable import Observable, ObservableType
import pytest
import responses
from engines.alienvault import AlienVaultEngine, parse_alienvault_response, get_endpoint
from models.alienvault import AlienvaultReport, PulseData
from utils.config import QueryError
from pathlib import Path
import copy
import json
from urllib.parse import quote
from requests.exceptions import HTTPError, ReadTimeout, Timeout
from pytest_mock import MockerFixture


@pytest.fixture(scope="session")
def fqdn_response_from_file():
    file_response: Path = Path("tests/api_responses/alienvault/fqdn_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ip_response_from_file():
    file_response: Path = Path("tests/api_responses/alienvault/ip_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture()
def md5_response():
    return {
        "sections": ["general", "analysis"],
        "type": "md5",
        "type_title": "FileHash-MD5",
        "indicator": "1fd35d9dc2eb919088f4eb48ab18b5a8",
        "validation": [],
        "base_indicator": {
            "id": 4084275658,
            "indicator": "a9ffd8047677bc2612cc97596c0c2386817ce80d",
            "type": "FileHash-SHA1",
            "title": "",
            "description": "",
            "content": "",
            "access_type": "public",
            "access_reason": "",
        },
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "id": "686b2966f904d473662ebd22",
                    "name": "malware",
                    "description": "",
                    "modified": "2025-07-07T03:51:15.250000",
                    "created": "2025-07-07T01:56:54.935000",
                    "tags": [],
                    "references": [],
                    "public": 1,
                    "adversary": "",
                    "targeted_countries": [],
                    "malware_families": [],
                    "attack_ids": [],
                    "industries": [],
                    "TLP": "white",
                    "cloned_from": None,
                    "export_count": 5,
                    "upvotes_count": 0,
                    "downvotes_count": 0,
                    "votes_count": 0,
                    "locked": False,
                    "pulse_source": "web",
                    "validator_count": 0,
                    "comment_count": 0,
                    "follower_count": 0,
                }
            ],
            "references": [],
            "related": {
                "alienvault": {"adversary": [], "malware_families": [], "industries": []},
                "other": {"adversary": [], "malware_families": [], "industries": []},
            },
        },
        "false_positive": [],
    }


@pytest.fixture()
def fqdn_response_missing_pulse_info(fqdn_response_from_file):
    input_data: dict = copy.deepcopy(fqdn_response_from_file)
    input_data.pop("pulse_info")
    return input_data


@pytest.fixture()
def fqdn_response_missing_indicator(fqdn_response_from_file):
    input_data: dict = copy.deepcopy(fqdn_response_from_file)
    input_data.pop("indicator")
    return input_data


@pytest.fixture()
def fqdn_response_missing_pulse_id(fqdn_response_from_file):
    input_data: dict = copy.deepcopy(fqdn_response_from_file)
    input_data["pulse_info"]["pulses"][0].pop("id")
    return input_data


# --- parse_alienvault_response tests ---


def test_parse_alienvault_fqdn(fqdn_response_from_file):
    report = parse_alienvault_response(fqdn_response_from_file)
    assert isinstance(report, AlienvaultReport)
    assert report.success is True
    assert report.count == 4
    assert len(report.pulse_data) == 4
    assert report.adversary == {"Lazarus"}
    assert "apnic" in report.malware_families
    assert report.link == "https://otx.alienvault.com/browse/global/pulses?q=support-gmeet.com"


def test_parse_alienvault_ip(ip_response_from_file):
    report = parse_alienvault_response(ip_response_from_file)
    assert isinstance(report, AlienvaultReport)
    assert report.success is True
    assert report.count == 1
    assert report.adversary == set()
    assert report.malware_families == set()
    assert report.link == "https://otx.alienvault.com/browse/global/pulses?q=186.180.44.234"


def test_parse_alienvault_md5(md5_response):
    report = parse_alienvault_response(md5_response)
    assert isinstance(report, AlienvaultReport)
    assert report.success is True
    assert report.count == 1
    titles = {p.title for p in report.pulse_data}
    assert "malware" in titles


def test_bad_or_empty_parse_alienvault(fqdn_response_missing_pulse_info):
    report = parse_alienvault_response(fqdn_response_missing_pulse_info)
    assert isinstance(report, AlienvaultReport)
    assert report.success is True
    assert report.count == 0
    assert report.pulse_data == set()


def test_missing_indicator_parse_alienvault(fqdn_response_missing_indicator):
    with pytest.raises(QueryError):
        _ = parse_alienvault_response(fqdn_response_missing_indicator)


def test_parse_alienvault_response_missing_pulse_id(fqdn_response_missing_pulse_id):
    report = parse_alienvault_response(fqdn_response_missing_pulse_id)
    assert report.count == 3
    assert len(report.pulse_data) == 3


# --- get_endpoint tests ---


@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        (ObservableType.IPV4, "1.1.1.1", "/indicators/IPv4/1.1.1.1/general"),
        (ObservableType.IPV6, "fe00::0", f"/indicators/IPv6/{quote('fe00::0')}/general"),
        (ObservableType.FQDN, "example.net", "/indicators/domain/example.net/general"),
        (
            ObservableType.SHA1,
            "3a30948f8cd5655fede389d73b5fecd91251df4a",
            "/indicators/file/3a30948f8cd5655fede389d73b5fecd91251df4a/general",
        ),
        (
            ObservableType.MD5,
            "781e5e245d69b566979b86e28d23f2c7",
            "/indicators/file/781e5e245d69b566979b86e28d23f2c7/general",
        ),
        (
            ObservableType.SHA256,
            "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882",
            "/indicators/file/84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882/general",
        ),
    ],
)
def test_get_endpoint(type: ObservableType, artifact: str, endpoint: str | None):
    result: str | None = get_endpoint(artifact, type)

    assert endpoint == result


# --- AlienVaultEngine.analyze() tests ---


@responses.activate
def test_analyze_fqdn(fqdn_observable, alienvault_secrets, fqdn_response_from_file):
    responses.add(
        responses.GET,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{fqdn_observable.value}/general",
        json=fqdn_response_from_file,
    )
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)
    assert isinstance(result, AlienvaultReport)
    assert result.success is True
    assert result.count == 4


def test_analyze_missing_api_key(fqdn_observable, alienvault_secrets_no_key):
    engine = AlienVaultEngine(alienvault_secrets_no_key, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)
    assert result.success is False
    assert result.error is not None


@responses.activate
def test_analyze_http_error(ip_observable, alienvault_secrets):
    responses.add(
        responses.GET,
        "https://otx.alienvault.com/api/v1/indicators/IPv4/186.180.44.234/general",
        body=HTTPError(),
    )
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(ip_observable)
    assert result.success is False


@responses.activate
@patch("time.sleep")
def test_analyze_timeout(mock_sleep, fqdn_observable, alienvault_secrets, mocker: MockerFixture):
    mocker.patch.object(AlienVaultEngine, "_make_request", side_effect=ReadTimeout)
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)
    assert result.success is False


# --- create_export_row tests ---


def test_create_export_row_with_result(alienvault_secrets, fqdn_response_from_file):
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    report = parse_alienvault_response(fqdn_response_from_file)
    row = engine.create_export_row(report)
    assert row["alienvault_pulses"] == 4
    assert row["alienvault_adversary"] == "Lazarus"


def test_create_export_row_none(alienvault_secrets):
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)
    assert row == {
        "alienvault_pulses": None,
        "alienvault_malwares": None,
        "alienvault_adversary": None,
    }


def test_create_export_row_no_malware_or_adversary(alienvault_secrets, ip_response_from_file):
    engine = AlienVaultEngine(alienvault_secrets, proxies={}, ssl_verify=True)
    report = parse_alienvault_response(ip_response_from_file)
    row = engine.create_export_row(report)
    assert row["alienvault_malwares"] is None
    assert row["alienvault_adversary"] is None
