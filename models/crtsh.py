from pydantic import BaseModel, Field, field_validator

from models.base_engine import BaseReport


class CrtShAPIResponseEntry(BaseModel):
    common_name: str = ""
    name_value: list[str] = Field(default_factory=list)
    """The following attributes are also present in the API response"""
    # issuer_ca_id: int
    # issuer_name: str
    # id: int
    # entry_timestamp: str
    # not_before: str
    # not_after: str
    # serial_number: str
    # result_count: int

    @field_validator("name_value", mode="before")
    @classmethod
    def validate_name_value(cls, value: str) -> list[str]:
        """The name_value field is natively a string containing newline-separated entries"""
        if not isinstance(value, str):
            raise ValueError("name_value must be a string")

        entries: list[str] = [v.strip() for v in value.split("\n")]

        return entries


class DomainCount(BaseModel):
    domain: str
    count: int


class CrtShReport(BaseReport):
    top_domains: list[DomainCount] = Field(default_factory=list)
    link: str = ""
