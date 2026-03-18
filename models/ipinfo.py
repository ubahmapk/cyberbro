from contextlib import suppress

import pycountry
from pydantic import ConfigDict, Field, model_validator

from models.report import BaseReport


def resolve_country_name(country_code: str) -> str:
    """Attempt to resolve country name

    Set the default to "Unknown" and suppress any exceptions.
    If it works, the name is replaced, otherwise we return the default
    """

    country_name: str = "Unknown"

    if not country_code:
        return country_name

    with suppress(Exception):
        country_obj = pycountry.countries.get(alpha_2=country_code)
        country_name = country_obj.name if country_obj else "Unknown"

    return country_name


class IpInfoReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    ip: str = ""
    bogon: bool = False
    city: str = Field(init_var=True, default="")
    region: str = Field(init_var=True, default="")
    country_code: str = Field(validation_alias="country", default="")
    asn: str = Field(validation_alias="org", default="Unknown")
    geolocation: str = Field(init=False, default="Unknown")
    country_name: str = ""
    hostname: str = "Unknown"
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def __validate_model__(self):
        if self.error:
            return self

        self.success = True
        self.link = f"https://ipinfo.io/{self.ip}"
        if self.bogon:
            self.hostname = "Private IP"
            self.country_name = "Bogon"
            self.asn = "BOGON"
            return self

        if self.city and self.region:
            self.geolocation = f"{self.city}, {self.region}"
        self.country_name = resolve_country_name(self.country_code)

        return self
