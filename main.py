
#!/usr/bin/python

__author__ = "Alan Saunders"
__purpose__ = "Use the RingCentral API to collect information on the instance, useful for conducting audits and health checks on RingCentral instances. Also runs local network diagnostics for VoIP readiness without any tenancy connection."
__version__ = "0.3"
__github__ = "https://github.com/Ripped-Kanga/RingCentral-Tools\n"
__disclaimer__ = "The purpose of this project is to provide easy auditability and administration of the RingCentral platform. Most modules are read-only (GET requests only). Modules that perform write operations will clearly indicate this and require explicit confirmation before making changes. To exit the script at any time, use CTRL + C. All audit data is written to CSV files stored in the /AuditResults folder."


# Import libraries
from client_auth.client import RingCentralOAuthClient, RingCentralJWTClient
from shared.api_utils import connection_test
from modules import user_audit, auto_receptionist, diagnostics, local_diagnostics, call_monitor, dnd_monitor
import argparse
import getpass
import os
import sys

from pick import pick

# set credentials and URLs
REDIRECTION_URI = "http://localhost:8000/callback"
AUTH_URL = "https://platform.ringcentral.com/restapi/oauth/authorize"
TOKEN_URL = "https://platform.ringcentral.com/restapi/oauth/token"
API_BASE_URL = "https://platform.ringcentral.com"

# Module registry — add new tenancy modules here as a display name: module mapping.
# Every module in this registry receives an authenticated client (OAuth or JWT).
MODULE_REGISTRY = {
    "User Extension Audit":          user_audit,
    "Auto-Receptionist Rules":       auto_receptionist,
    "Tenancy Diagnostics":           diagnostics,
    "Live Call Monitor":             call_monitor,
    "DND Status Monitor":            dnd_monitor,
    "Local Network Diagnostics":     local_diagnostics,
}

LOCAL_OPTION = "Run Local Diagnostics (no RingCentral account needed)"
TENANCY_OPTION = "Connect to a RingCentral Tenancy"
EXIT_OPTION = "Exit"

# Environment variable used to supply a JWT without putting it on the command
# line, where it would be visible in shell history and the process list.
JWT_ENV_VAR = "RINGCENTRAL_JWT"

OAUTH_AUTH_OPTION = "OAuth browser login (interactive, opens a browser)"
JWT_AUTH_OPTION = "JWT credential (no RingCentral login required)"


def choose_auth_method(args):
    """Resolve the authentication flow from the CLI, the environment, or a
    prompt. A JWT supplied by either route implies the JWT flow."""
    if args.auth:
        return args.auth
    if args.jwt or os.environ.get(JWT_ENV_VAR):
        return "jwt"

    chosen, _ = pick(
        [OAUTH_AUTH_OPTION, JWT_AUTH_OPTION],
        "How would you like to authenticate to the tenancy?",
        indicator="\u25BA\u25BA "
    )
    return "jwt" if chosen == JWT_AUTH_OPTION else "oauth"


def build_client(args):
    """Prompt for credentials as needed and return an authenticated client."""
    method = choose_auth_method(args)

    client_id = str(args.client_id) if args.client_id else input("Enter the Application Client ID: ")
    client_secret = str(args.client_secret) if args.client_secret else input("Enter the Application Client Secret: ")

    if method == "jwt":
        client = build_jwt_client(args, client_id, client_secret)
    else:
        client = build_oauth_client(args, client_id, client_secret)

    if args.clear_creds:
        client.clear_credentials()

    client.authenticate()

    # Verify connectivity and display company banner
    connection_test(client)
    return client


def build_oauth_client(args, client_id, client_secret):
    return RingCentralOAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=REDIRECTION_URI,
        auth_url=AUTH_URL,
        token_url=TOKEN_URL,
        api_base_url=API_BASE_URL
    )


def build_jwt_client(args, client_id, client_secret):
    """Build a client that authenticates with a JWT credential issued from the
    RingCentral developer console. The JWT is read from --jwt, then the
    environment, then an echo-free prompt, and is never written to disk."""
    jwt_assertion = args.jwt or os.environ.get(JWT_ENV_VAR)
    if not jwt_assertion:
        print(f"No JWT supplied via --jwt or ${JWT_ENV_VAR}.")
        jwt_assertion = getpass.getpass("Paste the JWT credential (input hidden): ")

    jwt_assertion = jwt_assertion.strip()
    if not jwt_assertion:
        raise ValueError("A JWT credential is required for JWT authentication.")

    return RingCentralJWTClient(
        client_id=client_id,
        client_secret=client_secret,
        jwt_assertion=jwt_assertion,
        token_url=TOKEN_URL,
        api_base_url=API_BASE_URL
    )


def tenancy_menu(client):
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
            module.run(client)
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
            client = build_client(args)
        except KeyboardInterrupt:
            print("\nAuthentication cancelled.")
            continue
        except Exception as e:
            print(f"Could not connect to the tenancy: {e}")
            input("Press Enter to return to the launch menu...")
            continue

        tenancy_menu(client)


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
        "--auth",
        choices=["oauth", "jwt"],
        help="Authentication flow to use. Defaults to jwt when a JWT is supplied, "
             "otherwise the tool asks at the tenancy prompt."
    )
    parser.add_argument(
        "--jwt",
        help=f"JWT credential for the JWT auth flow. Prefer the ${JWT_ENV_VAR} environment "
             "variable or the interactive prompt, so the token stays out of shell history."
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
