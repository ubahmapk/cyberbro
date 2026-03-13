import logging

import querycontacts
from pydantic import ValidationError

from models.abusix import AbusixReport
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class AbusixEngine(BaseEngine[AbusixReport]):
    @property
    def name(self):
        return "abusix"

    @property
    def supported_types(self):
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    def analyze(self, observable: Observable) -> AbusixReport:
        try:
            results = querycontacts.ContactFinder().find(observable.value)
            if not results:
                raise ValueError
            report: AbusixReport = AbusixReport(success=True, abuse_email=results[0])
        except ValueError:
            msg: str = f"No contact information returned for observable: {observable.value}"
            logger.warning(msg)
            return AbusixReport(success=False, error=msg)
        except ValidationError as e:
            msg: str = f"Error validating Abusix report for observable '{observable.value}': {e}"
            logger.error(msg, exc_info=True)
            return AbusixReport(success=False, error=msg)
        except Exception as e:
            msg: str = f"Error querying Abusix for observable '{observable.value}': {e}"
            logger.error(msg, exc_info=True)
            return AbusixReport(success=False, error=msg)

        return report

    def create_export_row(self, analysis_result: AbusixReport | None) -> dict:
        return {"abusix_abuse": analysis_result.abuse_email if analysis_result else None}
