import pytest
import requests
from requests.exceptions import HTTPError
import responses
from utils.config import QueryError

from pytest_mock import MockerFixture

from engines.abuseipdb import parse_abuseipdb_response, query_abuseipdb


@pytest.fixture()
def valid_api_response():
    return {
        "data": {
            "ipAddress": "1.1.1.1",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
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


@responses.activate
def test_query_abuseipdb(valid_api_response, ip_observable_dict, api_key):
    responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=valid_api_response)
    ip: str = ip_observable_dict["value"]

    response = query_abuseipdb(ip, api_key, None, False)

    assert response == valid_api_response


@responses.activate
def test_query_abuseipdb_http_error(api_key, ip_observable_dict):
    ip: str = ip_observable_dict["value"]
    responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", body=HTTPError())

    with pytest.raises(QueryError):
        response = query_abuseipdb(ip, api_key, None, False)


def test_request_timeout(ip_observable_dict, api_key, mocker: MockerFixture):
    mocker.patch("requests.get", side_effect=requests.exceptions.Timeout)

    with pytest.raises(QueryError):
        result = query_abuseipdb(ip_observable_dict, api_key, None, False)


def test_parse_abuseipdb_response(valid_api_response, ip_observable_dict):
    ip: str = ip_observable_dict["value"]
    expected: dict = {
        "reports": 24,
        "risk_score": 0,
        "link": "https://www.abuseipdb.com/check/1.1.1.1",
    }

    report: dict | None = parse_abuseipdb_response(valid_api_response, ip)

    assert report == expected


def test_missing_data_field_parse_abuseipdb(ip_observable_dict):
    ip: str = ip_observable_dict["value"]
    malformed_api_response: dict = {"not_a_data_field": "something else"}

    with pytest.raises(QueryError):
        report = parse_abuseipdb_response(malformed_api_response, ip)
