---
name: pytest-standards
description: Use this skill when writing, reviewing, modifying, or debugging pytest tests in this project. Activate when the user asks to add tests, fix a failing test, or review test files under tests/.
---

# Pytest Standards for cyberbro

## 1. Patch `time.sleep` on Connection-Error / Timeout Tests

`BaseEngine._make_request` is decorated with tenacity `@retry` using `wait_exponential`. Any test
that raises a `requests.exceptions.ConnectTimeout`, `ConnectionError`, or `Timeout` will trigger
3 real retries (~7 s of wall-clock sleep) unless `time.sleep` is patched.

**Rule:** Any test that simulates `ConnectTimeout` (or any exception type listed in the `retry_if_exception_type`
tuple in `models/base_engine.py`) MUST patch `time.sleep`.

**Pattern:**
```python
from unittest.mock import patch

@responses.activate
@patch("time.sleep")
def test_analyze_connection_error(mock_sleep, fqdn_observable, caplog):
    ...
```

Note: `@patch("time.sleep")` is the **inner** decorator so `mock_sleep` is the **first** parameter
(after fixtures injected by pytest). `@responses.activate` is the outer decorator.

**Not required for:** `HTTPError` (4xx/5xx) tests — `HTTPError` is not in the tenacity retry list.

## 2. HTTP Mocking with `responses`

Use the `responses` library for all HTTP mocking. Always use `@responses.activate` as the outermost
decorator and register the mock inside the test body:

```python
@responses.activate
def test_analyze_success(fqdn_observable):
    responses.add(responses.GET, CRTSH_JSON_URL, json=[...], status=200)
    ...
```

## 3. Fixture Naming and Ordering

Standard fixtures are defined in `conftest.py` or at the top of each test file. For engine tests,
the typical observable fixture is:

```python
@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)
```

When combining `@patch` with pytest fixtures, the patch mock always comes first in the parameter list.

## 4. Examples

For HTTP-based engines, use the `CrtSh` engine and associated tests as a reference.
For custom client-based engines, use the `Abusix` engine and associated tests as a reference.
