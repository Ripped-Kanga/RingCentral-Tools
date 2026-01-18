
#!/usr/bin/python

__author__ = "Alan Saunders"
__purpose__ = "Use the RingCentral API to collect information on the instance, useful for conducting audits and health checks on RingCentral instances."
__version__ = "0.1"
__github__ = "https://github.com/Ripped-Kanga/RingCentral-Tools\n"
__disclaimer__ = "The purpose of this project is to provide easy auditability to the RingCentral platform. All the API calls made in this project are GET requests and represent no danger to the RingCentral data. To exit the script at any time, use CTRL + C. All data collected by this tool is writen to CSV file, the file is stored in the /AuditResults folder."


# Import libraries
from client_auth.client import RingCentralOAuthClient
import argparse
# from dotenv import load_dotenv

# set credentials and URLs 
CLIENT_ID = None
CLIENT_SECRET = None
REDIRECTION_URI = "http://localhost:8000/callback"
AUTH_URL = "https://platform.ringcentral.com/restapi/oauth/authorize"
TOKEN_URL = "https://platform.ringcentral.com/restapi/oauth/token"
API_BASE_URL = "https://platform.ringcentral.com"



def main():
    # Setup cli_arguements
    parser = argparse.ArgumentParser(description="RingCentral-Tools")
    # Application Client ID arg
    parser.add_argument(
        "--client_id",
        help="Specify the Application Client ID to runtime, requires --client_secret to work."
    )

    parser.add_argument(
        "--client_secret",
        help="Specify the Application Client Secret to runtime, requires --client_id to work."
    )

    # Clear Stored Credentials arg
    parser.add_argument(
        "--clear-creds",
        action="store_true",
        help="Clear saved credentails and force re-authentication"
    )
    args = parser.parse_args()
    
    # Ask user for client ID and Secret. Skipps if --client_id and client_secret are set at arg.
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

    # Easy test GET to test if OAuth is working correctly.
    try:
        response = oauth_client.api_get("/restapi/v1.0/account/~/extension")
        for ext in response.get("records", []):
            print (f"Extension: {ext['extensionNumber']} - {ext['name']}")

    except Exception as e:
        print (f"API call failed: {e}") 



if __name__ == "__main__":
    main()
