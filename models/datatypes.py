from typing import Any, TypeAlias, TypedDict


class ObservableMap(TypedDict):
    value: str
    type: str


Proxies: TypeAlias = dict[str, str]

Report: TypeAlias = dict[str, Any]
