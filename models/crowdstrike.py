from typing import Annotated

from pydantic import Field

from models.report import BaseReport


class CrowdstrikeReport(BaseReport):
    device_count: int = 0
    link: str = ""
    indicator_found: bool = False
    published_date: str = ""
    last_updated: str = ""
    actors: Annotated[list[str], Field(default_factory=list)]
    malicious_confidence: str = ""
    threat_types: Annotated[list[str], Field(default_factory=list)]
    kill_chain: Annotated[list[str], Field(default_factory=list)]
    malware_families: Annotated[list[str], Field(default_factory=list)]
    vulnerabilities: Annotated[list[str], Field(default_factory=list)]
