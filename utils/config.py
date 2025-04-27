import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Secrets:
    abuseipdb: str = ""
    api_cache_timeout: int = 86400  # Default to 1 day
    api_prefix: str = "api"
    config_page_enabled: bool = False
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_falcon_base_url: str = "https://falcon.crowdstrike.com"
    google_safe_browsing: str = ""
    gui_cache_timeout: int = 1800
    gui_enabled_engines: list[str] = field(default_factory=list)
    ipinfo: str = ""
    max_form_memory_size: int = 1_048_576
    mde_client_id: str = ""
    mde_client_secret: str = ""
    mde_tenant_id: str = ""
    opencti_api_key: str = ""
    opencti_url: str = ""
    proxy_url: str = ""
    shodan: str = ""
    ssl_verify: bool = True
    virustotal: str = ""
    webscout: str = ""

    # Method to iterate through the dataclass fields
    def __iter__(self):
        """Iterate through the dataclass fields."""

        yield from self.__dataclass_fields__

    # TODO: Test the get and update methods
    # Add this get method to allow for a smooth transition from dict to dataclass
    def get(self, value: str) -> Any:
        """Get the value of a secret by its key."""

        if value in self.__dataclass_fields__:
            return self.__dict__[value]

        return None

    def update(self, updated_secrets: dict[str, Any]) -> None:
        """Update the secrets with new values."""

        for key, value in updated_secrets.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                print(f"Warning: {key} is not a valid secret key.")
                logger.warning(f"{key} is not a valid secret key.")


logger = logging.getLogger(__name__)

BASE_DIR: Path = Path.resolve(Path(__file__).parent)

logger.debug(f"{BASE_DIR=}")

# Define the path to the secrets file
SECRETS_FILE: Path = Path(BASE_DIR / "secrets.json")

# Initialize secrets dictionary with default values
DEFAULT_SECRETS: Secrets = Secrets()


def read_secrets_from_file(default_secrets: Secrets, secrets_file: Path) -> Secrets:
    """Load secrets from a JSON file, if it exists.

    Return a dictionary with any updated secrets.
    """

    # Make a copy of the defaults, we can compare for changes later
    secrets: Secrets = default_secrets

    # Load secrets from secrets.json if it exists
    if secrets_file.exists():
        try:
            with secrets_file.open() as f:
                secrets.update(json.load(f))
        except OSError as e:
            print(
                "Unable to read secrets file. Reading environment variables anyway..."
            )
            logger.debug(f"Error reading secrets file: {e}")
            logger.error(
                "Unable to read secrets file. Reading environment variables anyway..."
            )
        except json.JSONDecodeError as e:
            print("Error while decoding secrets:", e)
            logger.debug(f"Error while decoding secrets: {e}")
            logger.error(
                "Error while decoding secrets. Reading environment variables anyway..."
            )
        # TODO: Create custom Error class to handle invalid updates
    else:
        print("Secrets file not found. Reading environment variables anyway...")
        logger.info("Secrets file not found. Reading environment variables anyway...")

    return secrets


def read_secrets_from_env(secrets: Secrets) -> Secrets:
    """Load secrets from envrionment variables.

    Override the config file if the environment variable is set.
    """

    # Load secrets from environment variables - override the ones from secrets.json, if present
    env_configured: bool = False

    for key in secrets:
        env_value: str | None = os.getenv(key.upper())
        if env_value:
            env_configured: bool = True
            match key:
                case "gui_enabled_engines":
                    # Split the comma-separated list of engines into a list
                    secrets.gui_enabled_engines = [
                        engine.strip().lower() for engine in env_value.split(",")
                    ]
                case "config_page_enabled":
                    secrets.config_page_enabled = env_value.lower() in [
                        "true",
                        "1",
                        "yes",
                    ]
                case "ssl_verify":
                    secrets.ssl_verify = env_value.lower() in ["true", "1", "yes"]
                case _:
                    # update the dataclass field if it exists
                    secrets.update({key: env_value})

    if not env_configured:
        print(
            "No environment variables were configured. You can configure secrets later in secrets.json."
        )
        logger.info(
            "No environment variables were configured. You can configure secrets later in secrets.json."
        )

    return secrets


def save_secrets_to_file(secrets: Secrets, secrets_file: Path) -> None:
    """Save the secrets to a JSON file."""

    # Save the secrets to the secrets.json file
    try:
        with secrets_file.open("w") as f:
            json.dump(secrets, f, indent=4)
    except OSError as e:
        print(f"Unable to write secrets file: {e}")
        logger.error(f"Unable to write secrets file: {e}")
        return None
    except json.JSONDecodeError as e:
        print("Error while encoding secrets:", e)
        logger.error("Error while encoding secrets: %s", e)
        return None

    print("Secrets file was updated.")
    logger.info("Secrets file was updated.")

    return None


# @lru_cache
def get_config() -> Secrets:
    """Get the configuration for the application."""

    secrets: Secrets = read_secrets_from_file(DEFAULT_SECRETS, SECRETS_FILE)
    secrets = read_secrets_from_env(secrets)

    if not secrets.get("proxy_url"):
        print("No proxy URL was set. Using no proxy.")
        logger.info("No proxy URL was set. Using no proxy.")

    if secrets != DEFAULT_SECRETS:
        # If the secrets are not the same as the defaults, save them to the file

        if not SECRETS_FILE.exists():
            print(
                "Secrets file was not found. Attempting to save current values to a new one."
            )

        save_secrets_to_file(secrets, SECRETS_FILE)

    return secrets
