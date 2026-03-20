from typing import Annotated

from pydantic import ConfigDict, Field, model_validator

from models.report import BaseReport


class AbuseIPDBReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    ip_address: Annotated[str, Field(validation_alias="ipAddress")] = ""
    # is_public: bool = Field(validation_alias="isPublic")
    # ip_version: int = Field(validation_alias="ipVersion")
    is_whitelisted: Annotated[bool, Field(validation_alias="isWhitelisted")] = False
    risk_score: Annotated[int, Field(validation_alias="abuseConfidenceScore")] = 0
    is_tor: Annotated[bool, Field(validation_alias="isTor")] = False
    hostnames: Annotated[list[str], Field(default_factory=list[str])]
    country_code: Annotated[str, Field(validation_alias="countryCode")] = ""
    country_name: str = "Unknown"
    usage_type: Annotated[str, Field(validation_alias="usageType")] = ""
    domain: str = ""
    isp: str = ""
    reports: Annotated[int, Field(validation_alias="totalReports")] = 0
    # num_distinct_users: int = Field(validation_alias="numDistinctUsers", default=0)
    last_reported_at: Annotated[str, Field(validation_alias="lastReportedAt")] = ""
    link: Annotated[str, Field(init=False)] = ""

    @model_validator(mode="after")
    def __generate_link__(self):
        self.link = f"https://www.abuseipdb.com/check/{self.ip_address}"
        return self
