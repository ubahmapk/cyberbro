import json
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest
import responses
from engines.reversinglabs_spectra_analyze import get_api_endpoint, get_ui_endpoint, parse_rl_response
from pytest_mock import MockerFixture
from requests.exceptions import HTTPError, Timeout
from utils.config import QueryError

# Test constants
IP4 = "1.1.1.1"
IP6 = "fe00::0"
FQDN = "kosmicband.com"
URL = "https://example.com/level?api&text=3"
MD5 = "3a30948f8cd5655fede389d73b5fecd91251df4a"
SHA1 = "3a30948f8cd5655fede389d73b5fecd91251df4a"
SHA256 = "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"
API_URL = "https://a1000-example123.reversinglabs.com"


# Tests
@pytest.fixture(scope="session")
def fqdn_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/domain_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture()
def expected_fqdn_report():
    return {
        "observable": "FQDN",
        "reversed_success": False,
        "rl_analyze": {
            "link": f"{API_URL}/domain/{FQDN}/analysis/domain/",
            "malicious": 0,
            "malicious_files": 0,
            "report_color": "green",
            "report_type": "network",
            "reports": 13,
            "suspicious": 0,
            "suspicious_files": 0,
            "threats": [],
            "total_files": 0,
        },
        "type": "FQDN",
    }


@pytest.fixture()
def expected_fqdn_report_2():
    return {
        "link": f"{API_URL}/domain/{FQDN}/analysis/domain/",
        "malicious": 0,
        "malicious_files": 0,
        "report_color": "green",
        "report_type": "network",
        "reports": 13,
        "suspicious": 0,
        "suspicious_files": 0,
        "threats": [],
        "total_files": 0,
    }


@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        ("IPv4", IP4, f"/api/network-threat-intel/ip/{IP4}/report/"),
        ("IPv6", IP6, f"/api/network-threat-intel/ip/{IP6}/report/"),
        ("FQDN", FQDN, f"/api/network-threat-intel/domain/{FQDN}/"),
        (
            "URL",
            URL,
            f"/api/network-threat-intel/url/?url={quote_plus(URL)}",
        ),
        (
            "SHA1",
            SHA1,
            f"/api/samples/v3/{SHA1}/classification/?av_scanners=1",
        ),
        (
            "MD5",
            MD5,
            f"/api/samples/v3/{MD5}/classification/?av_scanners=1",
        ),
        (
            "SHA256",
            SHA256,
            f"/api/samples/v3/{SHA256}/classification/?av_scanners=1",
        ),
        ("NaN", IP4, None),
    ],
)
def test_get_api_endpoint(type: str, artifact: str, endpoint: str | None):
    result: str | None = get_api_endpoint(artifact, type)

    assert endpoint == result


@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        ("IPv4", IP4, f"/ip/{IP4}/analysis/ip/"),
        ("IPv6", IP6, f"/ip/{IP6}/analysis/ip/"),
        ("FQDN", FQDN, f"/domain/{FQDN}/analysis/domain/"),
        (
            "URL",
            URL,
            f"/url/{quote_plus(URL)}/analysis/url/",
        ),
        ("MD5", MD5, f"/{MD5}/"),
        ("SHA1", SHA1, f"/{SHA1}/"),
        (
            "SHA256",
            SHA256,
            f"/{SHA256}/",
        ),
        ("NaN", IP4, None),
    ],
)
def test_get_ui_endpoint(type: str, artifact: str, endpoint: str | None):
    result: str | None = get_ui_endpoint(artifact, type)

    assert endpoint == result


@pytest.mark.parametrize(
    "input_query_response,obs,type,url,expected_report",
    [
        ("fqdn_response_from_file", FQDN, "FQDN", API_URL, "expected_fqdn_report_2"),
    ],
)
def test_parse_rl_response(request: dict, input_query_response: dict, obs: str, type: str, url: str, expected_report: dict):
    """
    Use the built-in pytest fixture, request, to take the fixture name
    **as a string** in the parametrized list and retrieve the **actual**
    fixture data to be used in the test.

    """
    input: dict = request.getfixturevalue(input_query_response)
    expected: dict = request.getfixturevalue(expected_report)
    report: dict = parse_rl_response(input, obs, type, url)

    assert report == expected
