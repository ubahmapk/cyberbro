from pydantic import ConfigDict, EmailStr, Field

from models.report import BaseReport


class AbusixReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    abuse_email: EmailStr | None = Field(validation_alias="abuse", default=None)
