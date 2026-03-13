import logging
from collections import Counter

from pydantic import ValidationError
from requests.exceptions import ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout
from typing_extensions import override

from models.base_engine import BaseEngine
from models.crtsh import CrtShAPIResponseEntry, CrtShReport, DomainCount
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class CrtShEngine(BaseEngine[CrtShReport]):
    @property
    def name(self):
        return "crtsh"

    @property
    @override
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    def analyze(self, observable: Observable) -> CrtShReport:
        # If observable is a URL, extract domain
        if observable.type is ObservableType.URL:
            query_value: str = observable._return_fqdn_from_url()
            if not query_value:
                msg: str = f"Invalid URL passed to crtsh: {observable.value}"
                logger.error(msg)
                return CrtShReport(success=False, error=msg)
        else:
            query_value = observable.value

        url = "https://crt.sh/json"
        params: dict[str, str] = {"q": query_value}

        try:
            response = self._make_request(url, params=params, timeout=20)
            response.raise_for_status()

            results = response.json()

        except (ReadTimeout, ConnectTimeout):
            """
            Crt.sh can be **SLOW**, especially for large domains, or domains
            with a long certificate history.
            """
            msg: str = f"Timeout occurred while querying crt.sh for {observable.value}."
            logger.error(msg)
            return CrtShReport(success=False, error=msg)
        except HTTPError as e:
            msg: str = f"Error querying crt.sh for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return CrtShReport(success=False, error=msg)
        except JSONDecodeError as e:
            msg: str = (
                f"Unexpected error while parsing JSON response "
                f"from crt.sh for {observable.value}: {e!s}\n"
                f"Response: {response!s}"
            )
            logger.error(msg)
            logger.debug(response)
            return CrtShReport(success=False, error=msg)

        entries: list[CrtShAPIResponseEntry] = []
        for entry in results:
            try:
                entries.append(CrtShAPIResponseEntry(**entry))
            except ValidationError as e:
                msg: str = (
                    f"Unexpected error while validating response entry "
                    f"from crt.sh for {query_value}: {e!s}\n"
                    f"Response entry: {entry!s}"
                )
                logger.error(msg)

        domain_count: Counter = Counter()
        for entry in entries:
            domains: set[str] = set()
            domains.add(entry.common_name)
            for v in entry.name_value:
                domains.add(v)

            for domain in domains:
                domain_count[domain] += 1

        # Sort and extract top 5
        top_domains: list[DomainCount] = [
            DomainCount(domain=dmn, count=cnt) for dmn, cnt in domain_count.most_common(5)
        ]
        return CrtShReport(
            success=True,
            top_domains=top_domains,
            link=f"https://crt.sh/?q={query_value}",
        )

    def create_export_row(self, analysis_result: CrtShReport | None) -> dict:
        if not analysis_result:
            return {"crtsh_top_domains": None}

        domains = analysis_result.top_domains
        top_domains_str = ", ".join([d["domain"] for d in domains])

        return {"crtsh_top_domains": top_domains_str if top_domains_str else None}
