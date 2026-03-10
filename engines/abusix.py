import logging

import querycontacts
from pydantic import ConfigDict, EmailStr, Field, ValidationError

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from models.report import BaseReport

logger = logging.getLogger(__name__)


class AbusixReport(BaseReport):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    abuse_email: EmailStr | None = Field(validation_alias="abuse", default=None)


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
