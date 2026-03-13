# Engine Design Guide

This guide explains the architecture behind Cyberbro's engine system so contributors can understand how engines work before writing a single line of code.

For a step-by-step checklist of everything that must be done when adding an engine, see [Contributions](Contributions.md).

---

## Architecture Overview

Every engine is built from three pieces defined in `models/`:

| Class | File | Role |
|---|---|---|
| `BaseEngine[R]` | `models/base_engine.py` | Abstract base with HTTP helpers and the plugin contract |
| `BaseReport` | `models/report.py` | Pydantic model that holds engine output; auto-registered on subclass |
| `Observable` | `models/observable.py` | The value being analysed (IP, domain, hash, …) with its type flag |

The flow for a single analysis is:

```
caller → engine.analyze(observable: Observable) → MyReport
                   ↓ (HTTP engines only)
             engine._make_request(url, …) → requests.Response
```

Two engines serve as canonical references:

- **`engines/abuseipdb.py`** — HTTP engine with an API key, `model_validator`, and field aliasing.
- **`engines/abusix.py`** — Non-HTTP engine (uses a third-party library), no secrets required.

---

## `BaseReport` Subclass

```python
from pydantic import ConfigDict, Field, model_validator
from models.report import BaseReport

class MyEngineReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)

    # Field whose JSON key differs from the Python attribute name
    risk_score: int = Field(validation_alias="abuseConfidenceScore", default=0)
    country_name: str = "Unknown"
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def _build_link(self):
        self.link = f"https://example.com/check/{self.risk_score}"
        return self
```

Key points:

- `BaseReport` already defines `success: bool = False` and `error: str | None = None`. Do not redefine them.
- Use `Field(validation_alias=…)` to map camelCase JSON keys to snake_case attributes. Pair it with `ConfigDict(validate_by_alias=True, validate_by_name=True)` so the model accepts both the alias and the Python name.
- Use `model_validator(mode="after")` for computed fields that depend on other fields (e.g. building a URL from an IP address).
- **Auto-registration**: `BaseReport.__init_subclass__` automatically registers every subclass in `_REPORT_REGISTRY` by class name. No extra code is needed — simply subclassing `BaseReport` is enough.

---

## `BaseEngine` Subclass

```python
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

class MyEngine(BaseEngine[MyEngineReport]):
    @property
    def name(self) -> str:
        return "myengine"           # unique slug used in API responses and config

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self) -> bool:
        # Return True if the engine only supports IPs and should run
        # after a URL/domain has been resolved to an IP address.
        return True

    def analyze(self, observable: Observable) -> MyEngineReport:
        ...

    def create_export_row(self, analysis_result: MyEngineReport | None) -> dict:
        ...
```

`BaseEngine` is generic over the report type (`BaseEngine[MyEngineReport]`).

> **Note**: Always supply the report type parameter (`BaseEngine[MyReport]`). Omitting it is valid Python but defeats static analysis — the return type of `analyze()` will be inferred as the base class rather than your concrete report type.

### Required `@property` methods

| Property | Abstract? | Default | Description |
|---|---|---|---|
| `name` | yes | — | Unique slug, e.g. `"abuseipdb"` |
| `supported_types` | yes | — | Bitwise `ObservableType` flags |
| `execute_after_reverse_dns` | no | `False` | Set `True` for IP-only engines |
| `is_pivot_engine` | no | `False` | Set `True` only for DNS-pivot engines |

### Required methods

| Method | Signature | Description |
|---|---|---|
| `analyze` | `(observable: Observable) -> R` | Run the analysis, always return a report |
| `create_export_row` | `(analysis_result: R \| None) -> dict` | Return a flat `dict` for CSV/Excel export |

---

## `ObservableType` Flag Enum

`ObservableType` is an annotated alias for `ObservableFlag`, a `Flag` enum. Combine flags with `|`:

```python
from models.observable import ObservableType

# Single type
ObservableType.IPV4

# Multiple types
ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.FQDN
```

Available flags:

| Flag | Meaning |
|---|---|
| `CHROME_EXTENSION` | Chrome extension ID |
| `EMAIL` | Email address |
| `FQDN` | Fully-qualified domain name |
| `IPV4` | IPv4 address |
| `IPV6` | IPv6 address |
| `MD5` | MD5 hash |
| `SHA1` | SHA-1 hash |
| `SHA256` | SHA-256 hash |
| `URL` | Full URL |
| `BOGON` | Bogon / private IP space |

---

## API Key / Secrets Access

Engines receive a `Secrets` dataclass instance at construction time, available as `self.secrets`. Access keys by attribute name:

```python
def analyze(self, observable: Observable) -> MyEngineReport:
    api_key: str = self.secrets.myengine_api_key

    if not api_key:
        msg = "MyEngine API key not set"
        logger.warning(msg)
        return MyEngineReport(success=False, error=msg)

    # continue with analysis …
```

The early-return pattern keeps the rest of `analyze()` clean. If a key is missing, return a failed report immediately — do not raise.

To add a new key, add an attribute to the `Secrets` dataclass in `utils/config.py` with a sensible default (usually an empty string).

---

## `_make_request()` Pattern

For HTTP engines, use `self._make_request()` instead of calling `requests.get()` directly:

```python
from requests.exceptions import JSONDecodeError, RequestException
from pydantic import ValidationError

def query_api(self, api_key: str, observable: Observable) -> MyEngineReport:
    url = "https://api.example.com/v1/check"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    params = {"query": observable.value}

    try:
        response = self._make_request(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
    except RequestException as e:
        msg = f"MyEngine API error: {e}"
        logger.warning(msg)
        return MyEngineReport(success=False, error=msg)

    try:
        report = MyEngineReport(**response.json()["data"])
    except (KeyError, ValidationError, JSONDecodeError) as e:
        msg = f"MyEngine API response parsing error: {e}"
        logger.warning(msg)
        return MyEngineReport(success=False, error=msg)

    report.success = True
    return report
```

`_make_request()` wraps `requests.get()` with automatic retry (up to 3 attempts) and exponential back-off on `ConnectionError` and `Timeout`. Always:

1. Catch `RequestException` around the request itself.
2. Catch `KeyError`, `ValidationError`, and `JSONDecodeError` around the response parsing.
3. Return a failed `MyEngineReport` — never re-raise from `analyze()`.

---

## Testing Patterns

Tests live in `tests/engines/test_<enginename>.py`. Use the AbuseIPDB and Abusix tests as templates.

### Fixtures

```python
import pytest
from engines.myengine import MyEngine, MyEngineReport
from models.observable import Observable, ObservableType
from utils.config import Secrets

@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.myengine_api_key = "test_key"
    return s

@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.myengine_api_key = ""
    return s

@pytest.fixture
def ipv4_observable():
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)
```

### HTTP engines — mock with `@responses.activate`

```python
import responses

@responses.activate
def test_analyze_success(secrets_with_key, ipv4_observable):
    engine = MyEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.example.com/v1/check"

    responses.add(responses.GET, url, json={"data": {"risk": 42}}, status=200)

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.risk_score == 42
```

### Non-HTTP engines — mock with `unittest.mock.patch`

```python
from unittest.mock import patch

@patch("querycontacts.ContactFinder")
def test_analyze_success(mock_finder, secrets_with_config, ipv4_observable):
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_finder.return_value.find.return_value = ["abuse@example.com"]

    result = engine.analyze(ipv4_observable)

    assert result.success is True
    assert result.abuse_email == "abuse@example.com"
```

### Log assertions with `caplog`

```python
def test_analyze_no_api_key(secrets_without_key, ipv4_observable, caplog):
    engine = MyEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(ipv4_observable)

    assert result.success is False
    assert "API key not set" in caplog.text
```

### Required test coverage

Every engine must have tests for:

| Scenario | Priority |
|---|---|
| Successful analysis (all fields populated) | High |
| Missing API key (if applicable) | High |
| HTTP error responses (401, 403, 500) | High |
| Network timeout / connection error | Medium |
| Invalid / malformed JSON response | Medium |
| `create_export_row` with a valid report | Low |
| `create_export_row` with `None` | Low |
| `name`, `supported_types`, `execute_after_reverse_dns`, `is_pivot_engine` properties | Low |

For retry behaviour (timeout / connection error), patch `time.sleep` to avoid slowing down the test suite:

```python
from unittest.mock import patch

@responses.activate
@patch("time.sleep")
def test_analyze_timeout(mock_sleep, secrets_with_key, ipv4_observable, caplog):
    ...
```
