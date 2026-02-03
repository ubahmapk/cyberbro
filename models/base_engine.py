import logging
from abc import ABC, abstractmethod
from dataclasses import asdict
from enum import Flag, auto
from typing import Any

import requests
from pydantic.dataclasses import dataclass
from tenacity import after_log, retry, stop_after_attempt, wait_exponential

from utils.config import Secrets

logger = logging.getLogger(__name__)


class ObservableType(Flag):
    CHROME_EXTENSION = auto()
    EMAIL = auto()
    FQDN = auto()
    IPv4 = auto()
    IPv6 = auto()
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    URL = auto()
    BOGON = auto()


@dataclass(slots=True)
class Observable:
    type: ObservableType
    value: str

    def __hash__(self) -> int:
        """Set membership requires the object to be hashable"""
        return hash(self.value)


@dataclass(slots=True)
class BaseReport:
    success: bool
    error_msg: str | None = None

    def __iter__(self):
        yield from asdict(self)

    def __getitem__(self, key):
        return asdict(self)[key]

    def __json__(self):
        return asdict(self)

    def get(self, name, default: Any | None = None):
        return getattr(self, name, default)


class ExecutionPhase(Flag):
    """Defines the analysis phase(s) the engine should run duing."""

    EXTENSION = auto()  # Browser extension checks always run
    PRE_PIVOT = auto()
    PIVOT = auto()  # Can modify the observable in place (e.g. reverse DNS)
    POST_PIVOT = auto()
    DEPENDENT = auto()  # Engins that need results from other engines


class BaseEngine(ABC):
    """
    Abstract base class for all analysis engines.
    """

    def __init__(self, secrets: Secrets, proxies: dict, ssl_verify: bool):
        self.secrets = secrets
        self.proxies = proxies
        self.ssl_verify = ssl_verify

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique slug/name of the engine (e.g., 'abuseipdb')."""
        pass

    @property
    @abstractmethod
    def supported_types(self) -> ObservableType:
        """List of observable types this engine supports.
        e.g., SupportedTypes.IPv4 | SupportedTypes.URL
        """
        pass

    @property
    def execute_after_reverse_dns(self) -> bool:
        """
        If True, this engine runs in the second pass (Post-Pivot).
        Useful for engines that only support IP addresses (like Shodan),
        so they can benefit from a URL/Domain -> IP resolution.
        """
        return False

    @property
    def is_pivot_engine(self) -> bool:
        """
        If True, this engine is responsible for resolving the observable
        (e.g., Reverse DNS) to change its type/value for subsequent engines.
        """
        return False

    @abstractmethod
    def analyze(self, observable: Observable) -> BaseReport:
        """
        Perform the analysis.
        Returns the report object, including success or the error message, present.
        """
        pass

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        after=after_log(logger, logging.DEBUG),
    )
    def _make_request(
        self,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        timeout: int = 10,
    ) -> requests.Response:
        """Request data from the engine API.

        Up to 3 requests can be made before reraising the resulting
        API exception to the calling function.

        After each attempt, the delay between requests is exponentially increased
        and a DEBUG level log message is emitted.
        """
        response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=timeout)
        response.raise_for_status()
        return response

    @abstractmethod
    def create_export_row(self, analysis_result: Any) -> dict:
        """
        Format the raw result into a flat dictionary for CSV/Excel export.
        """
        pass
