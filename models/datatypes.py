from typing import Any, Protocol, Self, TypeAlias, TypedDict


class ObservableMap(TypedDict):
    value: str
    type: str


Proxies: TypeAlias = dict[str, str]

Report: TypeAlias = dict[str, Any]


class Engine(Protocol):
    SUPPORTED_OBSERVABLE_TYPES: list[str]
    NAME: str
    LABEL: str
    SUPPORTS: list[str]
    DESCRIPTION: str
    COST: str
    API_KEY_REQUIRED: bool
    MIGRATED: bool

    def run_engine(
        self: Self,
        observable: ObservableMap,
        proxies: Proxies,
        ssl_verify: bool,
    ) -> Report | None: ...
