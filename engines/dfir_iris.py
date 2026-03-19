import json
import logging

from pydantic import ValidationError
from requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
)

from models.base_engine import BaseEngine
from models.dfir_iris import DFIRAPIResponse, DFIRIrisReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class DFIRIrisEngine(BaseEngine):
    @property
    def name(self):
        return "dfir_iris"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
        )

    def _map_observable_to_search_body(self, observable: Observable) -> dict:
        # Use selective wildcards to match ioc
        match observable.type:
            case (
                ObservableType.IPV4
                | ObservableType.IPV6
                | ObservableType.MD5
                | ObservableType.SHA1
                | ObservableType.SHA256
                | ObservableType.BOGON
            ):
                body = {"search_value": f"%{observable.value}", "search_type": "ioc"}
            case ObservableType.FQDN | ObservableType.URL:
                body = {"search_value": f"{observable.value}%", "search_type": "ioc"}
            case _:
                body = {"search_value": f"{observable.value}", "search_type": "ioc"}

        return body

    def analyze(self, observable: Observable) -> DFIRIrisReport:
        dfir_iris_api_key = self.secrets.dfir_iris_api_key
        dfir_iris_url = self.secrets.dfir_iris_url

        if not all([dfir_iris_api_key, dfir_iris_url]):
            return DFIRIrisReport(success=False, error="DFIR-IRIS URL and API key must be set.")

        url = f"{dfir_iris_url}/search"
        params: dict[str, int] = {"cid": 1}
        headers = {
            "Authorization": f"Bearer {dfir_iris_api_key}",
            "Content-Type": "application/json",
        }

        body = self._map_observable_to_search_body(observable)

        try:
            payload = json.dumps(body)
            response = self._make_request_post(
                url,
                params=params,
                headers=headers,
                data=payload,
                timeout=5,
            )
            response.raise_for_status()
            cases: DFIRAPIResponse = DFIRAPIResponse(**response.json())
        except (ReadTimeout, ConnectTimeout):
            msg: str = f"Timeout occurred while posting data to DFIR-IRIS for {observable.value}."
            logger.error(msg)
            return DFIRIrisReport(success=False, error=msg)
        except HTTPError as e:
            msg: str = f"Error querying DFIR-IRIS for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return DFIRIrisReport(success=False, error=msg)
        except (JSONDecodeError, ValidationError) as e:
            msg: str = f"Error decoding JSON response from DFIR-IRIS for {observable.value}: {e!s}"
            logger.error(msg, exc_info=True)
            return DFIRIrisReport(success=False, error=msg)

        links: set[str] = set()
        for case in cases.data:
            link = f"{dfir_iris_url}/case/ioc?cid={case.case_id}"
            links.add(link)

        unique_links = sorted(links)
        return DFIRIrisReport(success=True, reports=len(unique_links), links=unique_links)

    def create_export_row(self, analysis_result: DFIRIrisReport | None) -> dict:
        if not analysis_result:
            return {"dfir_iris_total_count": 0, "dfir_iris_link": None}

        links_str = ", ".join(analysis_result.links)
        return {
            "dfir_iris_total_count": analysis_result.reports,
            "dfir_iris_link": links_str if links_str else None,
        }
