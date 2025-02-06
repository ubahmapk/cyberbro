import os
import json

import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

logging.debug("BASE_DIR: %s", BASE_DIR)

# Define the path to the secrets file
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.json')

# Initialize secrets dictionary with default values
secrets = {
    "proxy_url": "",
    "virustotal": "",
    "abuseipdb": "",
    "ipinfo": "",
    "google_safe_browsing": "",
    "mde_tenant_id": "",
    "mde_client_id": "",
    "mde_client_secret": "",
    "shodan": "",
    "opencti_api_key": "",
    "opencti_url": "", 
    "api_prefix": "api",
    "config_page_enabled": False,
    "gui_enabled_engines": []
}

# Load secrets from secrets.json if it exists
try:
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            secrets.update(json.load(f))
    else:
        print("Secrets file not found. Trying to read environment variables...")

        # Load secrets from environment variables
        for key in secrets.keys():
            env_value = os.getenv(key.upper())
            if env_value:
                if key == "gui_enabled_engines":
                    # Split the comma-separated list of engines into a list
                    secrets[key] = env_value.split(",")
                else:
                    secrets[key] = env_value

        # Check if mandatory variable is set
        if not secrets["proxy_url"]:
            logging.error("Error: No secrets.json file found and no environment variables set. Terminating the app.")
            exit(1)

        # Dump the variables and create the secrets.json file if at least proxy_url is set
        with open(SECRETS_FILE, 'w') as f:
            json.dump(secrets, f, indent=4)
        logging.info("Secrets file was automatically generated.")

except Exception as e:
    logging.error("Error while loading secrets: %s", e)
    exit(1)

def get_config():
    return secrets