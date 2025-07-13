from pydantic import BaseModel


class Certificate(BaseModel, extra="ignore"):
    common_name: str = ""
    name_value: str = ""
