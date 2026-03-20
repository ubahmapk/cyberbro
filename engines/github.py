import logging

from pydantic import ValidationError
from requests.exceptions import ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout

from models.base_engine import BaseEngine
from models.github import GithubReport, GrepAppResponse, SearchResults
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class GitHubEngine(BaseEngine[GithubReport]):
    @property
    def name(self):
        return "github"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
            | ObservableType.EMAIL
        )

    def analyze(self, observable: Observable) -> GithubReport:
        params: dict[str, str] = {"q": observable.value}

        try:
            response = self._make_request(
                url="https://grep.app/api/search",
                params=params,
                timeout=5,
            )
            response.raise_for_status()
            app_response: GrepAppResponse = GrepAppResponse(**response.json())
        except (ReadTimeout, ConnectTimeout):
            msg: str = f"Timeout occurred while querying grep.app for {observable.value}."
            logger.error(msg)
            return GithubReport(success=False, error=msg)
        except HTTPError as e:
            msg: str = f"Error querying grep.app for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return GithubReport(success=False, error=msg)
        except (JSONDecodeError, ValidationError) as e:
            msg: str = f"Error decoding JSON response from grep.app for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return GithubReport(success=False, error=msg)

        report: GithubReport = GithubReport(success=True)

        if not app_response.hits.total:
            # Report variables default to 0, so an empty result is just fine
            return report

        report.total = app_response.hits.total
        seen_repos = set()
        for hit in app_response.hits.hits:
            if hit.repo not in seen_repos:
                seen_repos.add(hit.repo)
                report.search_results.append(SearchResults(hit=hit))
            if len(report.search_results) >= 5:
                break

        return report

    def create_export_row(self, analysis_result: GithubReport | None) -> dict:
        # Since original export fields are missing, provide a count
        return {"github_results_count": analysis_result.total if analysis_result else None}
