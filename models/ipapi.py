from typing import Any

from pydantic import AnyUrl, BaseModel, EmailStr, Field, field_validator

from models.report import BaseReport


class IpapiCompany(BaseModel):
    name: str = ""
    abuser_score: str = ""
    domain: str = ""
    type: str = ""
    network: str = ""  # "4.0.0.0 - 4.127.255.255",
    whois: AnyUrl | None = None  # "https://api.ipapi.is/?whois=4.0.0.0"


class IpapiAbuse(BaseModel):
    name: str = ""
    address: str = ""
    email: EmailStr | None = None  # "abuse@level3.com",
    phone: str = ""  # "+1-877-453-8353"


class IpapiASN(BaseModel):
    asn: str = "Unknown"  # 3356,
    abuser_score: str = ""  # "0.0001 (Very Low)",
    route: str = ""  # "4.0.0.0/9",
    descr: str = ""  # "LEVEL3 - Level 3 Parent, LLC, US",
    country: str = ""  # "us",
    active: bool = False
    org: str = "Unknown"  # "Level 3 Parent, LLC",
    domain: str = ""  # "level3.com",
    abuse: EmailStr | None = None  # "abuse@level3.com",
    type: str = ""  # "isp",
    created: str = ""  # "2000-03-10",
    updated: str = ""  # "2018-02-20",
    rir: str = ""  # "ARIN",
    whois: AnyUrl | None = None  # "https://api.ipapi.is/?whois=AS3356"

    @field_validator("asn", mode="before")
    @classmethod
    def validate_asn(cls, v: Any) -> str:
        """
        The ASN field should always end up starting with the prefix "AS".
        This matches the previous data validation logic performed in the engine
        """
        if v == "Unknown":
            return v
        if isinstance(v, int):
            return f"AS{v}"
        if isinstance(v, str) and not v.startswith("AS"):
            return f"AS{v}"
        raise ValueError("ASN must be a string starting with 'AS' or an integer")


class IpapiLocation(BaseModel):
    is_eu_member: bool = False
    calling_code: str = ""  # "1",
    currency_code: str = ""  # "USD",
    continent: str = ""  # "NA",
    country: str = ""  # "United States",
    country_code: str = ""  # "US",
    state: str = ""  # "Hawaii",
    city: str = ""  # "Honolulu",
    latitude: float | None = None  # 21.3078,
    longitude: float | None = None  # -157.85919,
    zip: int | None = None  # "96898",
    timezone: str = ""  # "Pacific/Honolulu",
    local_time: str = ""  # "2026-04-03T10:13:34-10:00",
    local_time_unix: int | None = None  # 1775247214,
    is_dst: bool = False


class IpapiResponse(BaseModel):
    ip: str = ""
    rir: str = ""
    is_bogon: bool = False
    is_mobile: bool = False
    is_satellite: bool = False
    is_crawler: bool = False
    is_datacenter: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_abuser: bool = False
    company: IpapiCompany = Field(default_factory=IpapiCompany)
    abuse: IpapiAbuse = Field(default_factory=IpapiAbuse)
    asn: IpapiASN = Field(default_factory=IpapiASN)
    location: IpapiLocation = Field(default_factory=IpapiLocation)


class IpapiReport(BaseReport):
    ip: str = ""
    location: str = ""
    country: str = ""
    asn: str = ""
