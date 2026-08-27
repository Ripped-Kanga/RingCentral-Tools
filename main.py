
#!/usr/bin/python

__author__ = "Alan Saunders"
__purpose__ = "Use the RingCentral API to collect information on the instance, useful for conducting audits and health checks on RingCentral instances. Also runs local network diagnostics for VoIP readiness without any tenancy connection."
__version__ = "0.3"
__github__ = "https://github.com/Ripped-Kanga/RingCentral-Tools\n"
__disclaimer__ = "The purpose of this project is to provide easy auditability and administration of the RingCentral platform. Most modules are read-only (GET requests only). Modules that perform write operations will clearly indicate this and require explicit confirmation before making changes. To exit the script at any time, use CTRL + C. All audit data is written to CSV files stored in the /AuditResults folder."


# Import libraries
from client_auth.client import RingCentralOAuthClient
from shared.api_utils import connection_test
from modules import user_audit, auto_receptionist, diagnostics, local_diagnostics
import argparse
import sys

from pick import pick

# set credentials and URLs
REDIRECTION_URI = "http://localhost:8000/callback"
AUTH_URL = "https://platform.ringcentral.com/restapi/oauth/authorize"
TOKEN_URL = "https://platform.ringcentral.com/restapi/oauth/token"
API_BASE_URL = "https://platform.ringcentral.com"

# Module registry — add new tenancy modules here as a display name: module mapping.
# Every module in this registry receives an authenticated OAuth client.
MODULE_REGISTRY = {
    "User Extension Audit":          user_audit,
    "Auto-Receptionist Rules":       auto_receptionist,
    "Tenancy Diagnostics":           diagnostics,
    "Local Network Diagnostics":     local_diagnostics,
}

LOCAL_OPTION = "Run Local Diagnostics (no RingCentral account needed)"
TENANCY_OPTION = "Connect to a RingCentral Tenancy"
EXIT_OPTION = "Exit"


def build_client(args):
    """Prompt for credentials as needed and return an authenticated client."""
    client_id = str(args.client_id) if args.client_id else input("Enter the Application Client ID: ")
    client_secret = str(args.client_secret) if args.client_secret else input("Enter the Application Client Secret: ")

    oauth_client = RingCentralOAuthClient(
        client_id=client_id,
        client_secret=client_secret,
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
    return oauth_client


def tenancy_menu(oauth_client):
    """Module dispatch loop for an authenticated tenancy."""
    menu_options = list(MODULE_REGISTRY.keys()) + ["Back to Launch Menu", EXIT_OPTION]

    while True:
        chosen, _ = pick(menu_options, "Select a module to run:", indicator="►► ")

        if chosen == EXIT_OPTION:
            print("Exiting. Goodbye.")
            sys.exit(0)
        if chosen == "Back to Launch Menu":
            return

        module = MODULE_REGISTRY[chosen]
        try:
            module.run(oauth_client)
        except KeyboardInterrupt:
            print("\nModule interrupted by user.")
        except Exception as e:
            print(f"Module '{chosen}' encountered an error: {e}")

        input("Press Enter to return to the module menu (or CTRL+C to exit)...")


def launch_menu(args):
    """Top-level menu. Authentication only happens on the tenancy path, so the
    local diagnostics can be run on a customer site with no RingCentral app
    credentials to hand."""
    options = [LOCAL_OPTION, TENANCY_OPTION, EXIT_OPTION]

    while True:
        chosen, _ = pick(options, "What would you like to do?", indicator="►► ")

        if chosen == EXIT_OPTION:
            print("Exiting. Goodbye.")
            sys.exit(0)

        if chosen == LOCAL_OPTION:
            try:
                local_diagnostics.run()
            except KeyboardInterrupt:
                print("\nLocal diagnostics interrupted by user.")
            except Exception as e:
                print(f"Local diagnostics encountered an error: {e}")
            continue

        try:
            oauth_client = build_client(args)
        except KeyboardInterrupt:
            print("\nAuthentication cancelled.")
            continue
        except Exception as e:
            print(f"Could not connect to the tenancy: {e}")
            input("Press Enter to return to the launch menu...")
            continue

        tenancy_menu(oauth_client)


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
    parser.add_argument(
        "--local",
        action="store_true",
        help="Skip the launch menu and go straight to local diagnostics."
    )
    args = parser.parse_args()

    if args.local:
        local_diagnostics.run()
        sys.exit(0)

    launch_menu(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by keyboard (CTRL + C). Exiting.")
        sys.exit(130)
