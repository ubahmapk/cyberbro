import pytest
from models.datatypes import ObservableMap, Proxies


@pytest.fixture()
def proxies():
    return Proxies({"https": "", "http": ""})


@pytest.fixture()
def ssl_verify() -> bool:
    return True


@pytest.fixture()
def ip_observable_dict() -> ObservableMap:
    return ObservableMap({"value": "1.1.1.1", "type": "IPv4"})


@pytest.fixture()
def fqdn_observable_dict() -> ObservableMap:
    return {"value": "example.net", "type": "FQDN"}


@pytest.fixture()
def url_observable_dict() -> ObservableMap:
    return {"value": "https://www.example.com", "type": "URL"}


@pytest.fixture()
def api_key() -> str:
    return "test_api_key"
