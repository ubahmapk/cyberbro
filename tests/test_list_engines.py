import pytest
from types import SimpleNamespace

from utils.list_engines import list_engine_metadata, EngineModule, load_engines


class Module(SimpleNamespace):
    """
    For testing, we don't want to load **real** Modules, and the `EngineModule`
    is only a Protocol abstraction. So DuckType matching is all that is required
    to pass the test.
    """

    SUPPORTED_OBSERVABLE_TYPES: list[str]
    NAME: str
    LABEL: str
    SUPPORTS: list[str]
    DESCRIPTION: str
    COST: str
    API_KEY_REQUIRED: bool


@pytest.fixture()
def selected_engines_list():
    return ["alienvault", "ipinfo", "github"]


@pytest.fixture()
def selected_engines_list_with_chrome_extension(selected_engines_list):
    new_list: list[str] = selected_engines_list.copy()
    new_list.append("extension")
    return new_list


@pytest.fixture()
def expected_engine_list_with_chrome_extension(selected_engines_list):
    new_list: list[str] = selected_engines_list.copy()
    new_list.append("chrome_extension")
    return sorted(new_list)


@pytest.mark.parametrize(
    "engine_list, expected_result",
    [
        ("selected_engines_list", "selected_engines_list"),
        ("selected_engines_list_with_chrome_extension", "expected_engine_list_with_chrome_extension"),
    ],
)
def test_load_engines(request, engine_list, expected_result):
    engine_list = request.getfixturevalue(engine_list)
    expected_list = request.getfixturevalue(expected_result)

    loaded_engines: list[EngineModule] = load_engines(engine_list)

    returned_names: list[str] = [e.NAME for e in loaded_engines]

    assert sorted(returned_names) == sorted(expected_list)


@pytest.fixture()
def engine_module_list():
    alienvault: Module = Module(
        SUPPORTED_OBSERVABLE_TYPES=["FQDN", "IPv4"],
        NAME="alienvault",
        LABEL="Alientvault",
        SUPPORTS=["hash", "IP", "domain", "url", "risk"],
        DESCRIPTION="Checks Alienvault for IP, domain, URL, hash",
        COST="Free",
        API_KEY_REQUIRED=True,
    )

    ipinfo: Module = Module(
        SUPPORTED_OBSERVABLE_TYPES=["IPv4", "IPv6"],
        NAME="ipinfo",
        LABEL="IPInfo",
        SUPPORTS=["IP"],
        DESCRIPTION="Checks IPinfo for IP, reversed obtained IP for a given domain/URL, free API key required.",
        COST="Free",
        API_KEY_REQUIRED=True,
    )

    github: Module = Module(
        SUPPORTED_OBSERVABLE_TYPES=["CHROME_EXTENSION", "FQDN", "IPv4", "IPv6", "MD5"],
        NAME="github",
        LABEL="Github",
        SUPPORTS=["domain", "URL", "IP", "hash", "scraping", "chrome_extension_id", "edge_extension_id"],
        DESCRIPTION="Get Github grep.app API search results for all types of observable",
        COST="Free",
        API_KEY_REQUIRED=False,
    )

    return [alienvault, ipinfo, github]


@pytest.fixture()
def expected_engine_module_list_report():
    expected_report: dict = {
        "alienvault": {
            "label": "Alientvault",
            "description": "Checks Alienvault for IP, domain, URL, hash",
            "supports": ["hash", "IP", "domain", "url", "risk"],
            "cost": "Free",
            "api_key_required": True,
            "supported_observable_types": ["FQDN", "IPv4"],
        },
        "ipinfo": {
            "label": "IPInfo",
            "description": "Checks IPinfo for IP, reversed obtained IP for a given domain/URL, free API key required.",
            "supports": ["IP"],
            "cost": "Free",
            "api_key_required": True,
            "supported_observable_types": ["IPv4", "IPv6"],
        },
        "github": {
            "label": "Github",
            "description": "Get Github grep.app API search results for all types of observable",
            "supports": ["domain", "URL", "IP", "hash", "scraping", "chrome_extension_id", "edge_extension_id"],
            "cost": "Free",
            "api_key_required": False,
            "supported_observable_types": ["CHROME_EXTENSION", "FQDN", "IPv4", "IPv6", "MD5"],
        },
    }

    return expected_report


def test_list_engine_metadata(engine_module_list, expected_engine_module_list_report):
    report = list_engine_metadata(engine_module_list)

    assert report == expected_engine_module_list_report


@pytest.fixture()
def bad_engine_module_list(engine_module_list):
    bad_module: Module = Module(
        NAME="github",
        LABEL="Github",
        SUPPORTS=["domain", "URL", "IP", "hash", "scraping", "chrome_extension_id", "edge_extension_id"],
        DESCRIPTION="Get Github grep.app API search results for all types of observable",
        COST="Free",
        API_KEY_REQUIRED=False,
    )

    bad_module_list: list[Module] = engine_module_list.copy()
    bad_module_list.append(bad_module)

    return bad_module_list


def test_list_engine_metadata_bad_module(bad_engine_module_list, expected_engine_module_list_report):
    """
    The bad_engine_module_list addes one bad module to the end of the list.
    That bad module should be ignored, so the resulting list should match
    the passing test above
    """

    report = list_engine_metadata(bad_engine_module_list)

    assert report == expected_engine_module_list_report
