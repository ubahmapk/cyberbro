from pydantic import BaseModel, Field

from models.report import BaseReport


class DFIRCase(BaseModel):
    case_id: int
    case_name: str


class DFIRAPIResponse(BaseModel):
    data: list[DFIRCase]


class DFIRIrisReport(BaseReport):
    reports: int = 0
    links: list[str] = Field(default_factory=list)
