import logging

import querycontacts

from models.datatypes import ObservableMap, Report

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

NAME: str = "abusix"
LABEL: str = "Abusix"
SUPPORTS: list[str] = ["abuse", "IP"]
DESCRIPTION: str = "Checks abuse contact with Abusix for IP, reversed obtained IP for a given domain/URL"
COST: str = "Free"
API_KEY_REQUIRED: bool = False


def run_engine(observable_dict: ObservableMap, *args, **kwargs) -> Report | None:
    """
    Queries the Abusix service for contact information related to the given observable.

    Args:
        observable (str): The observable (e.g., IP address, domain) to query.

    Returns:
        dict: A dictionary with the key "abuse", containing the returned contact info
              (e.g., abuse email address). For example:
                  {
                      "abuse": "abuse@example.com"
                  }
        None: If an error occurs or no contact information is found.
    """
    ip: str = observable_dict["value"]

    try:
        results = querycontacts.ContactFinder().find(ip)
        if not results:
            logger.warning("No contact information returned for observable: %s", ip)
            return None

        # We assume the first item in 'results' is the most relevant contact
        return {"abuse": results[0]}

    except Exception as e:
        logger.error("Error querying Abusix for observable '%s': %s", ip, e, exc_info=True)

    # Return None if any error or unexpected scenario occurred
    return None
