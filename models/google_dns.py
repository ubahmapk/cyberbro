from enum import Enum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from models.report import BaseReport


class DNSRequestType(Enum):
    """DNS request types.

    Used to control the request loop.
    """

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28


class DNSRecordType(Enum):
    """Enriched DNS answer types.

    Used in the report to specify SPF and DMARC vs generic TXT records
    """

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    SPF = "SPF"
    DMARC = "DMARC"
    AAAA = 28


class DNSAnswer(BaseModel):
    """The API response model for a single DNS record within a DNS response.

    This model mirrors the response and the values should not be changed during processing.
    """

    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    name: str = ""
    type: DNSRequestType
    ttl: int = Field(0, validation_alias="TTL")
    data: str


class GoogleDNSResponse(BaseModel):
    """The API response model for a DNS query response.

    This model mirrors the response and the values should not be changed during processing.
    """

    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    status: int = Field(0, validation_alias="Status")
    answer: list[DNSAnswer] = Field(default_factory=list, validation_alias="Answer")


class DNSEntry(BaseModel):
    """The parsed, enriched DNS record, returned in the engine report."""

    name: str = ""
    type: DNSRecordType
    ttl: int = Field(0, validation_alias="TTL")
    data: str = ""

    @computed_field
    @property
    def type_name(self) -> str:
        return self.type.name

    @model_validator(mode="after")
    def _validate_model(self) -> Self:
        # Enrich TXT records if they are SPF or DMARC
        if self.type is DNSRecordType.TXT:
            match self.data.lower():
                case data if data.startswith("v=dmarc1"):
                    self.type = DNSRecordType.DMARC
                case data if data.startswith("spf"):
                    self.type = DNSRecordType.SPF

        # Trip the MX record to just the domain name
        if self.type is DNSRequestType.MX:
            self.data = self.data.strip().split(" ")[-1]

        return self


class GoogleDNSReport(BaseReport):
    answers: list[DNSEntry] = Field(default_factory=list)

    @computed_field
    @property
    def dmarc_present(self) -> bool:
        for entry in self.answers:
            if entry.type is DNSRequestType.TXT and entry.data.lower().startswith("v=dmarc1"):
                return True
        return False

    @computed_field
    @property
    def spf_present(self) -> bool:
        for entry in self.answers:
            if entry.type is DNSRequestType.TXT and entry.data.lower().startswith("v=spf1"):
                return True
        return False
