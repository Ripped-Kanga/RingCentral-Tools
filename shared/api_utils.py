import sys
import time
import requests


def rate_limit_get(client, endpoint):
    """Wraps client.api_get() with rate-limit handling, 404/4xx tolerance, and 5xx retry."""
    while True:
        try:
            return client.api_get(endpoint)
        except requests.HTTPError as e:
            status = e.response.status_code
            if status == 429:
                retry_after = int(e.response.headers.get('Retry-After', 60))
                print(f'Rate limit hit. Pausing {retry_after} seconds before retrying...')
                time.sleep(retry_after)
            elif 400 <= status < 500:
                # 404 (not found), 400 (unsupported rule, e.g. AWR-193), etc.
                return None
            elif status >= 500:
                print(f'Server error {status}. Retrying in 5 seconds...')
                time.sleep(5)
            else:
                raise


def rate_limit_post(client, endpoint, json_body):
    """Wraps client.api_post() with rate-limit handling and 5xx retry.
    Unlike rate_limit_get, 4xx errors are raised — a failed POST means bad
    input or insufficient permissions that the user needs to know about."""
    while True:
        try:
            return client.api_post(endpoint, json_body)
        except requests.HTTPError as e:
            status = e.response.status_code
            if status == 429:
                retry_after = int(e.response.headers.get('Retry-After', 60))
                print(f'Rate limit hit. Pausing {retry_after} seconds before retrying...')
                time.sleep(retry_after)
            elif status >= 500:
                print(f'Server error {status}. Retrying in 5 seconds...')
                time.sleep(5)
            else:
                raise


def fetch_extension_map(client):
    """id -> (extensionNumber, name) for every extension on the account, so
    per-extension events can be labelled with numbers instead of raw IDs."""
    ext_map = {}
    page = 1
    while True:
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension?perPage=1000&page={page}')
        if resp is None:
            return ext_map
        for e in resp.get('records', []):
            ext_map[str(e['id'])] = (e.get('extensionNumber', ''), e.get('name', ''))
        if page >= resp.get('paging', {}).get('totalPages', 1):
            return ext_map
        page += 1


def connection_test(client):
    """
    Verifies API connectivity and prints company info.
    Prompts the user to confirm the account before proceeding.
    """
    account_resp = rate_limit_get(client, '/restapi/v2/accounts/~')
    service_resp = rate_limit_get(client, '/restapi/v1.0/account/~/service-info')

    if account_resp is None:
        sys.exit("Failed to reach the RingCentral API. Check your credentials and try again.")

    company_name = account_resp.get('companyName', 'N/A')
    company_status = account_resp.get('status', 'N/A')
    company_number = account_resp.get('mainNumber', 'N/A')

    rc_plan = 'N/A'
    rc_billing = 'N/A'
    if service_resp:
        rc_plan = service_resp.get('servicePlan', {}).get('name', 'N/A')
        rc_billing = service_resp.get('billingPlan', {}).get('durationUnit', 'N/A')

    print('#' * 80)
    print('\u25BA\u25BA\u25BA Company Information')
    print('#' * 80)
    print(f'Company Name   - {company_name}')
    print(f'Company Status - {company_status}')
    print(f'Company Number - {company_number}')
    print()
    print('#' * 80)
    print('\u25BA\u25BA\u25BA Plan and Billing')
    print('#' * 80)
    print(f'Plan: {rc_plan}  |  Billing: {rc_billing}')
    print()

    while True:
        confirm = input("Confirm the company information above is correct (y/n): ").strip().lower()
        if confirm == 'y':
            print("Confirmed.\n")
            break
        elif confirm == 'n':
            sys.exit("Aborted. Please check your credentials and client app settings.")
        print("Please enter 'y' or 'n'.")
