import logging

from bs4 import BeautifulSoup
from bs4.exceptions import ParserRejectedMarkup
from requests.exceptions import RequestException

from models.base_engine import BaseEngine, BaseReport
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class ChromeExtensionReport(BaseReport):
    name: str = ""
    url: str = ""


class ChromeExtensionEngine(BaseEngine[ChromeExtensionReport]):
    @property
    def name(self):
        # NOTE: The original analysis logic uses "extension" as the result key,
        # but the engine file is named chrome_extension.py. Sticking to the file name
        # for consistency with the new system, but the old analysis.py logic
        # for CHROME_EXTENSION type would need a slight tweak or this engine needs
        # to be run in a dedicated pre-loop logic like the original, as it's not selected by users.
        return "chrome_extension"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.CHROME_EXTENSION

    def _fetch_extension_name(self, url: str) -> ChromeExtensionReport:
        try:
            response = self._make_request(url, timeout=5)
            response.raise_for_status()
        except RequestException as e:
            msg: str = f"Error searching for extension: {e}"
            logger.warning(msg)
            return ChromeExtensionReport(success=False, error=msg)

        name: str = ""
        try:
            soup = BeautifulSoup(response.content, "html.parser")

            if "microsoftedge.microsoft.com" in url:
                if title_tag := soup.find("title"):
                    name = title_tag.text.strip().split("-")[0].strip()
            else:
                if h1_tag := soup.find("h1"):
                    name = h1_tag.text.strip()
        except ParserRejectedMarkup as e:
            msg: str = f"Error while parsing response from URL '{url}': {e}"
            logger.error(msg, exc_info=True)
            return ChromeExtensionReport(success=False, error=msg)

        if name:
            return ChromeExtensionReport(success=True, name=name, url=url)

        # No Extension found
        return ChromeExtensionReport(success=False, error="No extension found")

    def analyze(self, observable: Observable) -> ChromeExtensionReport:
        chrome_url = f"https://chromewebstore.google.com/detail/{observable.value}"
        edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{observable.value}"

        result = self._fetch_extension_name(chrome_url)
        if result.success:
            return result

        # No extension found at Chrome URL, try Edge URL
        # If this report does not succeed, return it anyway for error reporting
        return self._fetch_extension_name(edge_url)

    def create_export_row(self, analysis_result: ChromeExtensionReport | None) -> dict:
        # Note: In the original export.py, this was explicitly handled for the
        # "CHROME_EXTENSION" type using the "extension" key in the result.
        # This implementation aligns with the goal of moving all logic into the class.
        if not analysis_result or not analysis_result.success:
            return {"extension_name": None}

        return {"extension_name": analysis_result.name}
