import logging

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from models.report import BaseReport

logger = logging.getLogger(__name__)


class IpapiLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    city: str | None = None
    state: str | None = None
    country: str | None = None
    country_code: str | None = None


class IpapiAsn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    asn: str = "Unknown"
    org: str | None = None

    @field_validator("asn", mode="after")
    @classmethod
    def prefix_as(cls, v: str) -> str:
        if v and v != "Unknown" and not v.startswith("AS"):
            return f"AS{v}"
        return v


class IpapiVpn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    service: str | None = None
    url: str | None = None


class IpapiReport(BaseReport):
    model_config = ConfigDict(extra="ignore")
    ip: str = ""
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_abuser: bool = False
    location: IpapiLocation = Field(default_factory=IpapiLocation)
    asn: IpapiAsn = Field(default_factory=IpapiAsn)
    vpn: IpapiVpn = Field(default_factory=IpapiVpn)
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def __validate_model__(self):
        if self.error:
            return self
        self.success = True
        self.link = f"https://ipapi.is/{self.ip}"
        return self
