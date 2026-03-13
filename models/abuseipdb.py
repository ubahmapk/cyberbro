from pydantic import ConfigDict, Field, model_validator

from models.report import BaseReport


class AbuseIPDBReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    ip_address: str = Field(validation_alias="ipAddress", default="")
    # is_public: bool = Field(validation_alias="isPublic")
    # ip_version: int = Field(validation_alias="ipVersion")
    is_whitelisted: bool = Field(validation_alias="isWhitelisted", default=False)
    risk_score: int = Field(validation_alias="abuseConfidenceScore", default=0)
    is_tor: bool = Field(validation_alias="isTor", default=False)
    # hostnames: list[str] = Field(default_factory=list[str])
    country_code: str = Field(validation_alias="countryCode", default="")
    country_name: str = "Unknown"
    usage_type: str = Field(validation_alias="usageType", default="")
    domain: str = ""
    isp: str = ""
    reports: int = Field(validation_alias="totalReports", default=0)
    # num_distinct_users: int = Field(validation_alias="numDistinctUsers", default=0)
    last_reported_at: str = Field(validation_alias="lastReportedAt", default="")
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def __generate_link__(self):
        self.link = f"https://www.abuseipdb.com/check/{self.ip_address}"
        return self
