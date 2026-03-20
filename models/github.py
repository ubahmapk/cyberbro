from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from models.report import BaseReport


class GrepAppHit(BaseModel):
    model_config = ConfigDict(extra="ignore")  # forward-proof against new fields
    repo: str
    branch: str
    path: str


class GrepAppHitsContainer(BaseModel):
    total: int
    hits: list[GrepAppHit]


class GrepAppResponse(BaseModel):
    hits: GrepAppHitsContainer


class SearchResults(BaseModel):
    hit: GrepAppHit = Field(init_var=True)
    title: str = Field(init=False, default="")
    url: str = Field(init=False, default="")
    description: str = Field(init=False, default="")

    @model_validator(mode="after")
    def set_url(self) -> Self:
        self.title = self.hit.repo
        self.description = self.hit.path
        self.url = f"https://github.com/{self.hit.repo}/blob/{self.hit.branch}/{self.hit.path}"
        return self


class GithubReport(BaseReport):
    search_results: list[SearchResults] = Field(default_factory=list)
    total: int = 0
