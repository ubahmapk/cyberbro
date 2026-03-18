from __future__ import annotations

from enum import StrEnum, auto
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from models.report import BaseReport

# Keywords to identify legitimate cloud/hosting providers that can be abused
LEGITIMATE_PROVIDER_KEYWORDS: set[str] = {
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "vultr",
    "cloudflare",
    "oracle",
    "ibm",
    "alibaba",
    "tencent",
    "rackspace",
    "contabo",
    "scaleway",
}

# High-risk countries for cybersecurity threats
HIGH_RISK_COUNTRIES: set[str] = {
    "RU",
    "CN",
    "UA",
    "IR",
    "KP",
    "MD",
    "SC",  # Russia, China, Ukraine, Iran, N.Korea, Moldova, Seychelles
    "BY",
    "PK",
    "BD",
    "VN",
    "BG",
    "RO",  # Belarus, Pakistan, Bangladesh, Vietnam, Bulgaria, Romania
    "IN",
    "HK",
    "TR",
    "ID",
    "LT",
    "AL",
    "EE",  # India, Hong Kong, Turkey, Indonesia, Lithuania, Albania, Estonia
}


class AsnSource(StrEnum):
    SPAMHAUS = auto()
    LETHAL_FORENSICS = auto()
    BRIANHAMA = auto()

    def __str__(self) -> str:
        return self.name.replace("_", " ").title()


def _is_legitimate_provider(name: str) -> bool:
    source_lower = name.lower()
    return any(keyword in source_lower for keyword in LEGITIMATE_PROVIDER_KEYWORDS)


class AsnEntry(BaseModel):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    asn: str
    # rir: str
    domain: str = ""
    cc: str = ""
    name: str = Field(validation_alias="asname", default="")
    sources: set[AsnSource] = Field(init=False, default_factory=set)

    @computed_field
    @property
    def is_legit(self) -> bool:
        return _is_legitimate_provider(self.name)

    @field_validator("asn", mode="before")
    @classmethod
    def validate_asn(cls, v: Any) -> str:
        if isinstance(v, int):
            return str(v)
        return v

    @field_validator("sources", mode="before")
    @classmethod
    def validate_sources(cls, v: Any) -> set:
        if isinstance(v, (list, set)):
            return {AsnSource(item) if isinstance(item, str) else item for item in v}
        return v

    @computed_field
    @property
    def calculate_risk_score(self) -> int:
        risk_score: int = 50  # Base score for being in a bad ASN list

        # Factor 1: Presence in authoritative sources
        sources_count: int = len(self.sources)
        if sources_count >= 3:
            risk_score += 30  # In all three lists = very high confidence
        elif sources_count == 2:
            risk_score += 20  # In two lists = higher confidence
        elif AsnSource.SPAMHAUS in self.sources:
            risk_score += 10  # Spamhaus is more authoritative
        elif AsnSource.LETHAL_FORENSICS in self.sources:
            risk_score += 8  # LETHAL-FORENSICS focuses on VPN/anonymization services

        # Factor 2: Legitimate provider penalty
        if _is_legitimate_provider(self.name):
            risk_score -= 30

        # Factor 3: High-risk countryyy location
        if self.cc.upper() in HIGH_RISK_COUNTRIES:
            risk_score += 10

        # Ensure scorre stays within bounds
        return max(0, min(100, risk_score))

    def __add__(self, other: Any) -> AsnEntry:
        if not (isinstance(other, AsnEntry)):
            return NotImplemented

        if self.asn != other.asn:
            raise ValueError(f"Cannot add ASN {other.asn} to ASN {self.asn}")

        new_entry: AsnEntry = AsnEntry(
            asn=self.asn,
            domain=self.domain,
            cc=self.cc,
            name=self.name,
        )

        # Add description from both entries
        if other.name:
            new_entry.name = f"{self.name}; {other.name}"

        # Add country code from other entry if not present
        if not new_entry.cc and other.cc:
            new_entry.cc = other.cc

        # Add domain from other entry if not present
        if not new_entry.domain and other.domain:
            new_entry.domain = other.domain

        # Add sources from both entries
        new_entry.sources = self.sources | other.sources

        return new_entry


class BadAsnStatus(StrEnum):
    POTENTIALLY_LEGITIMATE = auto()
    POTENTIALLY_ABUSED = auto()
    LEGITIMATE_BUT_ABUSED = auto()
    MALICIOUS = auto()
    UNLISTED = auto()
    UNKNOWN = auto()


class BadAsnReport(BaseReport):
    status: BadAsnStatus = BadAsnStatus.UNKNOWN
    asn: str = ""
    sources: set[AsnSource] = Field(default_factory=set)
    details: str = ""
    legitimate_but_abused: bool = False
    risk_score: int = 0
    asn_org_name: str = ""

    @field_validator("sources", mode="before")
    @classmethod
    def validate_sources(cls, v: Any) -> set:
        if isinstance(v, (list, set)):
            return {AsnSource(item) if isinstance(item, str) else item for item in v}
        return v
