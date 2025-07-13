import pytest
import responses

from models.datatypes import ObservableMap, Proxies, Report
from engines.chrome_extension import fetch_extension_page, parse_extension_name
from requests.exceptions import HTTPError
from utils.config import QueryError


@pytest.fixture()
def chrome_base_url() -> str:
    return "https://chromewebstore.google.com/detail/"


@pytest.fixture()
def edge_base_url() -> str:
    return "https://microsoftedge.microsoft.com/addons/detail/"


@pytest.fixture()
def chrome_extension_url(chrome_base_url) -> str:
    """1Password Chrome extension ID"""
    return f"{chrome_base_url}/bkdgflcldnnnapblkhphbgpggdiikppg"


@pytest.fixture()
def edge_extension_url(edge_base_url):
    """1Password Edge extension ID"""
    return f"{edge_base_url}/khgocmkkpikpnmmkgmdnfckapcdkgfaf"


@responses.activate
def test_fetch_extension_page_httperror(chrome_extension_url, proxies):
    responses.add(responses.GET, f"{chrome_extension_url}", body=HTTPError())

    with pytest.raises(QueryError):
        _ = fetch_extension_page(chrome_extension_url, proxies, True)
