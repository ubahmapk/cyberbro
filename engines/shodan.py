import json
import logging
from typing import Any, Self

import requests
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

class ShodanResponse(BaseModel):
    """Basic Shodan response model.

    Shodan returns a more comprehensive JSON object,
    but these are the key fields Cyberbro reports on.
    """

    ip: str = Field(init=False, default="", alias="ip_str")
    ports: list[int] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    tags: list[Any] = Field(default_factory=list)
    link: str = Field(init=False, default="")

    @model_validator(mode="after")
    def _generate_link(self) -> Self:
        self.link = f"https://api.shodan.io/shodan/host/{self.ip}"

        return self


def query_shodan(
    observable: str, api_key: str, proxies: dict[str, str], ssl_verify: bool = True
) -> dict[str, Any] | None:
    """
    Queries the Shodan API for information about a given observable (typically an IP).

    Args:
        observable (str): The IP address to query in Shodan.
        api_key (str): The Shodan API key.
        proxies (dict): A dictionary of proxy configurations.

    Returns:
        dict: Contains the data about open ports, tags, and a link to the Shodan host page.
              Example:
              {
                  "ports": [...],
                  "tags": [...],
                  "link": "https://www.shodan.io/host/<IP>"
              }
        None: If the request was unsuccessful or an error occurred.
    """
    headers: dict = {"Accept": "application/json"}
    params: dict = {"key": api_key}
    url: str = f"https://api.shodan.io/shodan/host/{observable}"

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )

        # Shodan returns an HTTP 404 status if there is no data available for the host
        if response.status_code == 404:
            logger.info(f"No Shodan data found for host {observable}")
            return None

        # Catch all other HTTP error codes
        response.raise_for_status()
    except requests.HTTPError as e:
        logger.error(f"Error retrieving Shodan API response for {observable}: {e=}", exc_info=True)
        return None

    try:
        report: ShodanResponse = ShodanResponse(**response.json())
    except requests.JSONDecodeError as e:
        logger.error(f"Error decoding response into JSON object for {observable}: {e=}", exc_info=True)
        return None

    return json.loads(report.model_dump_json())
