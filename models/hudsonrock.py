from typing import TypeAlias, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from models.base_engine import BaseReport

# ******************** Email Queries and Reports ********************


class StealerEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    computer_name: str = ""
    operating_system: str = ""
    date_compromised: str = ""
    total_corporate_services: int = 0
    total_user_services: int = 0
    # ip: str = ""
    # malware_path: str = ""
    # antiviruses: list[str] = Field(default_factory=list)
    # top_passwords: list[str] = Field(default_factory=list)
    # top_logins: list[str] = Field(default_factory=list)


class HudsonRockEmailResponse(BaseModel):
    message: str = ""
    stealers: list[StealerEntry] = Field(default_factory=list)
    total_corporate_services: int = 0
    total_user_services: int = 0


class HudsonRockEmailReport(BaseReport):
    model_config = ConfigDict(extra="ignore")
    email: str = ""
    stealers: list[StealerEntry] = Field(default_factory=list)
    total_corporate_services: int = 0
    total_user_services: int = 0


# ******************** FQDN Queries and Reports ********************


class UrlEntry(BaseModel):
    occurrence: int = 0
    type: str = ""
    url: str = ""


class FqdnData(BaseModel):
    model_config = ConfigDict(extra="ignore")
    employees_urls: list[UrlEntry] = Field(default_factory=list)
    clients_urls: list[UrlEntry] = Field(default_factory=list)
    all_urls: list[UrlEntry] = Field(default_factory=list)


class FqdnStats(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total_employees: int = Field(validation_alias="totalEmployees", default=0)
    total_users: int = Field(validation_alias="totalUsers", default=0)
    employees_urls: list[str] = Field(default_factory=list)
    clients_urls: list[str] = Field(default_factory=list)
    # employees_count: list[int] = Field(default_factory=list)
    # clients_count: list[int] = Field(default_factory=list)


class AntiVirusEntry(BaseModel):
    name: str = ""
    count: int = 0


class Applications(BaseModel):
    keyword: str = ""


class Passwords(TypedDict):
    totalPass: int
    too_weak: dict[str, int]
    weak: dict[str, int]
    medium: dict[str, int]
    strong: dict[str, int]


class Antiviruses(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total: int = 0
    found: float = 0.0
    not_found: float = 0.0
    free: float = 0.0
    av_list: list[AntiVirusEntry] = Field(validation_alias="list", default_factory=list)


class ThirdPartyDomainEntry(BaseModel):
    occurrence: int = 0
    domain: str | None = ""


class StealerFamilies(BaseModel):
    name: str = ""
    count: int = 0


class HudsonRockFqdnResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_by_alias=True, validate_by_name=True)
    total: int = 0
    total_stealers: int = Field(validation_alias="totalStealers", default=0)
    employees: int = 0
    users: int = 0
    third_parties: int = 0
    # logo: AnyUrl | None = None
    data: FqdnData | None = None
    total_urls: int = Field(validation_alias="totalUrls", default=0)
    stats: FqdnStats | None = None
    is_shopify: bool = False
    last_employee_compromised: str = ""
    last_user_compromised: str = ""
    antiviruses: Antiviruses = Field(default_factory=Antiviruses)
    applications: list[Applications] = Field(default_factory=list)
    # employee_passwords: dict = Field(validation_alias="employeePasswords", default_factory=dict)
    # user_passwords: dict = Field(validation_alias="userPasswords", default_factory=dict)
    third_party_domains: list[ThirdPartyDomainEntry] = Field(
        validation_alias="thirdPartyDomains", default_factory=list
    )

    """
    First keyword in stealerFamilies is "total".
    All other keys are stealer family names - but at the same structural level as the total
    e.g.

    "stealerFamilies": {
        "total": 50000,
        "RedLine": 21217,
        "UNKNOWN": 2103,
        "CRYPTBOT": 1157,
        ...
    },
    """
    stealer_families: dict[str, int] = Field(
        validation_alias="stealerFamilies", default_factory=dict
    )


class HudsonRockFqdnReport(BaseReport):
    model_config = ConfigDict(extra="ignore")
    total: int = 0
    employees: int = 0
    users: int = 0
    third_parties: int = 0
    total_urls: int = 0
    last_employee_compromised: str = ""
    last_user_compromised: str = ""
    applications: set[str] = Field(default_factory=set)
    stealer_families: int = 0
    total_stealers: int = 0
    clients_urls: list[UrlEntry] = Field(default_factory=list)
    employees_urls: list[UrlEntry] = Field(default_factory=list)
    is_shopify: bool = False
    # third_party_domains: list[ThirdPartyDomainEntry] = Field(default_factory=list)
    # all_urls: list[UrlEntry] = Field(default_factory=list)
    # total_corporate_services: int = 0
    # total_user_services: int = 0


# The engine can return either of these types, so alias them together
# to keep things simple
HudsonRockReport: TypeAlias = HudsonRockFqdnReport | HudsonRockEmailReport
