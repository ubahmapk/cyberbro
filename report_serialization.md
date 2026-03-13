# `models/report.py` — Serialization & Deserialization Overview

This module implements a **self-describing, registry-based** pattern so that `BaseReport` subclasses can round-trip through JSON/dict without losing their concrete type.

---

## The Type Registry

```python
_REPORT_REGISTRY: dict[str, type] = {}
```

A module-level dict that maps class names (strings) to their class objects. It's populated automatically via `__init_subclass__`:

```python
def __init_subclass__(cls, **kwargs):
    super().__init_subclass__(**kwargs)
    _REPORT_REGISTRY[cls.__name__] = cls
```

Every time a subclass of `BaseReport` is defined (e.g., `class VirusTotalReport(BaseReport)`), Python automatically calls `__init_subclass__`, registering the new class. No manual registration is needed — just defining the subclass is sufficient.

---

## Serialization — `__json__`

```python
@model_serializer
def __json__(self) -> dict:
    d = {name: getattr(self, name) for name in type(self).model_fields}
    d["__cls__"] = type(self).__name__
    return d
```

The `@model_serializer` decorator hooks into Pydantic's serialization pipeline. When `.model_dump()` or `json.dumps()` is called on any report instance, this method runs and:

1. Iterates over the **concrete subclass's** declared fields (`model_fields`) — not just `BaseReport`'s fields — so subclass-specific data is included.
2. Injects a `"__cls__"` key containing the class name as a string (e.g., `"VirusTotalReport"`).

This `__cls__` tag is the sentinel that makes deserialization type-safe.

---

## Deserialization — `from_dict`

```python
@classmethod
def from_dict(cls, data: dict) -> "BaseReport":
    data = dict(data)          # defensive copy — avoids mutating caller's dict
    cls_name = data.pop("__cls__", None)
    klass = _REPORT_REGISTRY.get(cls_name, cls)
    return klass(**data)
```

1. **Defensive copy** — `dict(data)` prevents side effects on the caller's original dict when `__cls__` is popped.
2. **Type resolution** — looks up the class by name in the registry. Falls back to `cls` (whatever class `from_dict` was called on) if `__cls__` is missing or unrecognized.
3. **Instantiation** — passes remaining fields as keyword arguments to the resolved class constructor (standard Pydantic model construction).

You can call `from_dict` on any class in the hierarchy — `BaseReport.from_dict(data)` or `VirusTotalReport.from_dict(data)` — and you get back the correct concrete type.

---

## Key Contributor Takeaways

| Concern | How it's handled |
|---|---|
| Defining a new report type | Just subclass `BaseReport` — registration is automatic |
| Preserving type through serialization | `"__cls__"` field injected automatically by `__json__` |
| Reconstructing correct type from dict | `from_dict` resolves class from registry using `"__cls__"` |
| Mutation safety | `from_dict` copies the dict before popping `__cls__` |
| Accessing fields dict-style | `get(name, default)` delegates to `getattr` for convenience |

## Important: Import Order

The subclass module **must be imported** before `from_dict` is called, otherwise `__init_subclass__` hasn't run and the registry won't contain the entry. Ensure all report subclass modules are imported at application startup.
