from pydantic import BaseModel, ConfigDict, Field, model_validator

from models.report import BaseReport


class IpapiLocation(BaseModel):
    city: str = ""
    state: str = ""
    country: str = ""
    country_code: str = ""


class IpapiAsn(BaseModel):
    asn: str = "Unknown"
    org: str = ""


class IpapiVpn(BaseModel):
    service: str = ""
    url: str = ""


class IpapiReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    ip: str = ""
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_abuser: bool = False
    location: IpapiLocation = Field(default_factory=IpapiLocation)
    asn: IpapiAsn = Field(default_factory=IpapiAsn)
    vpn: IpapiVpn = Field(default_factory=IpapiVpn)
    link: str = Field(init=False, default="")

    @model_validator(mode="before")
    @classmethod
    def __normalize_asn__(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data

        asn_data = data.get("asn")

        if not asn_data:
            data["asn"] = {"asn": "Unknown", "org": ""}
        elif isinstance(asn_data, dict) and "asn" in asn_data:
            asn_val = str(asn_data["asn"])
            if asn_val and not asn_val.startswith("AS"):
                data["asn"]["asn"] = f"AS{asn_val}"

        return data

    @model_validator(mode="after")
    def __generate_link__(self) -> "IpapiReport":
        if self.error:
            return self
        self.success = True
        if self.ip:
            self.link = f"https://api.ipapi.is/?q={self.ip}"
        return self
