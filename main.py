
#!/usr/bin/python

__author__ = "Alan Saunders"
__purpose__ = "Use the RingCentral API to collect information on the instance, useful for conducting audits and health checks on RingCentral instances."
__version__ = "0.2"
__github__ = "https://github.com/Ripped-Kanga/RingCentral-Tools\n"
__disclaimer__ = "The purpose of this project is to provide easy auditability and administration of the RingCentral platform. Most modules are read-only (GET requests only). Modules that perform write operations will clearly indicate this and require explicit confirmation before making changes. To exit the script at any time, use CTRL + C. All audit data is written to CSV files stored in the /AuditResults folder."


# Import libraries
from client_auth.client import RingCentralOAuthClient
from shared.api_utils import connection_test
from modules import user_audit, auto_receptionist, diagnostics
import argparse
import sys

from pick import pick

# set credentials and URLs
CLIENT_ID = None
CLIENT_SECRET = None
REDIRECTION_URI = "http://localhost:8000/callback"
AUTH_URL = "https://platform.ringcentral.com/restapi/oauth/authorize"
TOKEN_URL = "https://platform.ringcentral.com/restapi/oauth/token"
API_BASE_URL = "https://platform.ringcentral.com"

# Module registry — add new modules here as a display name: module mapping
MODULE_REGISTRY = {
    "User Extension Audit":          user_audit,
    "Auto-Receptionist Rules":       auto_receptionist,
    "Diagnostics":                   diagnostics,
}


def main():
    # Setup cli_arguments
    parser = argparse.ArgumentParser(description="RingCentral-Tools")
    parser.add_argument(
        "--client_id",
        help="Specify the Application Client ID at runtime, requires --client_secret to work."
    )
    parser.add_argument(
        "--client_secret",
        help="Specify the Application Client Secret at runtime, requires --client_id to work."
    )
    parser.add_argument(
        "--clear-creds",
        action="store_true",
        help="Clear saved credentials and force re-authentication"
    )
    args = parser.parse_args()

    CLIENT_ID = str(args.client_id) if args.client_id else input("Enter the Application Client ID: ")
    CLIENT_SECRET = str(args.client_secret) if args.client_secret else input("Enter the Application Client Secret: ")

    oauth_client = RingCentralOAuthClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECTION_URI,
        auth_url=AUTH_URL,
        token_url=TOKEN_URL,
        api_base_url=API_BASE_URL
    )

    if args.clear_creds:
        oauth_client.clear_credentials()

    oauth_client.authenticate()

    # Verify connectivity and display company banner
    connection_test(oauth_client)

    # Module dispatch loop
    menu_options = list(MODULE_REGISTRY.keys()) + ["Exit"]

    while True:
        chosen, _ = pick(menu_options, "Select a module to run:", indicator="\u25BA\u25BA ")

        if chosen == "Exit":
            print("Exiting. Goodbye.")
            sys.exit(0)

        module = MODULE_REGISTRY[chosen]
        try:
            module.run(oauth_client)
        except KeyboardInterrupt:
            print("\nModule interrupted by user.")
        except Exception as e:
            print(f"Module '{chosen}' encountered an error: {e}")

        input("Press Enter to return to the main menu (or CTRL+C to exit)...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by keyboard (CTRL + C). Exiting.")
        sys.exit(130)
