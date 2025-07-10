from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class OpenPort(BaseModel):
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None


class IDSAlert(BaseModel):
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None


class CurrentOpenedPorts(BaseModel):
    count: int
    data: list[OpenPort] = Field(default_factory=list)


class IDSAlerts(BaseModel):
    count: int
    data: list[IDSAlert] = Field(default_factory=list)


class Issues(BaseModel):
    is_anonymous_vpn: bool = False
    is_cloud: bool = False
    is_darkweb: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_proxy: bool = False
    is_scanner: bool = False
    is_snort: bool = False
    is_tor: bool = False
    is_vpn: bool = False


class WhoisRecord(BaseModel):
    as_name: str | None = None
    as_no: int | None = None
    city: str | None = None
    region: str | None = None
    org_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    org_country_code: str | None = None
    confirmed_time: str | None = None


class Whois(BaseModel):
    count: int = 0
    data: list[WhoisRecord] = Field(default_factory=list)


class ScoreStatus(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class Score(BaseModel):
    inbound: ScoreStatus | None = None
    outbound: ScoreStatus | None = None

    @field_validator("inbound", "outbound", mode="before")
    @classmethod
    def _validate_score_status(cls, value: Any) -> str | None:
        """Validate the score field."""
        match value:
            case None:
                return None
            case str() as score_str:
                return score_str.lower()
            case _:
                raise ValueError("Score must be a string or None")


class SuspiciousInfoReport(BaseModel):
    status: int
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts | None = None
    ids: IDSAlerts | None = None
    ip: str = ""
    issues: Issues | None = None
    representative_domain: str = ""
    score: Score | None = None
    whois: Whois | None = None

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        # If the status is anything other than 2xx, raise an error
        if not 199 < self.status < 300:
            raise ValueError(
                f"Unable to generate Suspicious Info Report for IP: {self.ip}. Status Code: {self.status}"
                f"{self.model_dump_json()}"
            )
        return self
