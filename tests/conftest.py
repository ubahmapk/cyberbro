import pytest
from models.observable import Observable, ObservableType
from utils.config import Secrets


@pytest.fixture(scope="session")
def fqdn_observable():
    return Observable(value="example.net", type=ObservableType.FQDN)


@pytest.fixture(scope="session")
def url_observable():
    return Observable(value="https://www.example.com", type=ObservableType.URL)


@pytest.fixture(scope="session")
def ip_observable():
    """Oops. Duplicate
    Search tests and replace with ipv4_observable"""
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture(scope="session")
def ipv4_observable():
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture(scope="session")
def ipv6_observable():
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


@pytest.fixture(scope="session")
def api_key() -> str:
    return "test_api_key"


@pytest.fixture(scope="session")
def empty_secrets():
    return Secrets()


# Additional fixtures for IPAPI tests
@pytest.fixture(scope="session")
def secrets_with_key():
    s = Secrets()
    s.ipapi = "X" * 20
    return s


@pytest.fixture(scope="session")
def secrets_without_key():
    s = Secrets()
    s.ipapi = ""
    return s
