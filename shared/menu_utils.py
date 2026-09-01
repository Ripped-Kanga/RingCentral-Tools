import sys
import time
import textwrap
from urllib.parse import urlencode

from pick import pick

from shared.api_utils import rate_limit_get


def resolve_extensions(client, max_count):
    """Prompt for extension numbers and resolve each to an extension record.
    Returns a list of records, or None if the user backs out. Used by the live
    monitor modules to turn user-entered numbers into extension IDs."""
    while True:
        raw = input(
            f'\nExtension number(s) to monitor, comma-separated '
            f'(max {max_count}, blank to cancel): '
        ).strip()
        if not raw:
            return None
        numbers = [n.strip() for n in raw.split(',') if n.strip()]
        if not all(n.isdigit() for n in numbers):
            print('Please enter numeric extension numbers only.')
            continue
        if len(numbers) > max_count:
            print(
                f'{len(numbers)} extensions requested — above {max_count}, '
                'use account-level monitoring instead.'
            )
            continue

        found, missing = [], []
        for number in dict.fromkeys(numbers):  # de-duplicate, keep order
            resp = rate_limit_get(
                client, f'/restapi/v1.0/account/~/extension?{urlencode({"extensionNumber": number})}'
            )
            records = (resp or {}).get('records', [])
            if records:
                found.append(records[0])
            else:
                missing.append(number)

        if missing:
            print(f'Not found on this account: {", ".join(missing)}')
        if not found:
            print('No extensions matched. Please try again.')
            continue

        print('\nExtensions to monitor:')
        for e in found:
            print(f"  ext {e.get('extensionNumber', '?'):<6} {e.get('name', '')}")
        confirm = input('Proceed with these extensions? (y/n): ').strip().lower()
        if confirm == 'y':
            return found


def audit_checker(client, audit_url):
    """
    Fetch the total extension count and present filter options.
    Returns (filter_user_count, total_user_count, built_url).
    filter_user_count is False if no filter was applied (all extensions).
    """
    resp = rate_limit_get(client, audit_url)
    total = resp['paging']['totalElements']

    print(f'\n{"#" * 80}')
    print(f'\u25BA\u25BA\u25BA Found {total} extensions')
    print(f'{"#" * 80}\n')

    advisory = (
        "You can customise the filter parameters to control which extensions are returned. "
        "Most elements in RingCentral count as extensions (Users, Call Queues, IVR Menus, etc.). "
        "Selecting no filter will return all extensions, which may result in some fields being None "
        "for non-User extension types."
    )
    print(textwrap.fill(advisory, width=80))
    print()

    while True:
        ask = input("Do you want to customise the API filter parameters? (y/n): ").strip().lower()
        if ask in ('y', 'n'):
            break
        print("Please enter 'y' or 'n'.")

    if ask == 'n':
        print("No filter applied, proceeding with all extensions...\n")
        return False, total, f'/restapi/v1.0/account/~/extension?perPage={total}'

    options = ['System (filter by type/status)', 'Specific (filter by number/email)']
    chosen, _ = pick(options, 'Are you auditing a whole system or specific users?', indicator='\u25BA\u25BA ')

    if 'System' in chosen:
        return audit_checker_system(client, total)
    else:
        return audit_checker_specific(client, total)


def audit_checker_system(client, total_elements):
    """Filter extensions by type and status using interactive menus."""
    type_map = {
        'User': 'User',
        'Call Queue': 'Department',
        'Announcement': 'Announcement',
        'Voicemail': 'Voicemail',
        'IVR Menu': 'IvrMenu',
        'Limited Extensions': 'Limited',
        'Site': 'Site',
        'Park Locations': 'ParkLocation',
    }
    status_map = {
        'Not Activated': 'NotActivated',
    }

    while True:
        type_selections = pick(
            list(type_map.keys()),
            'Select (SPACE) extension type(s) to filter for. Press ENTER to confirm:',
            multiselect=True,
            min_selection_count=1,
            indicator='\u25BA\u25BA '
        )
        extension_types = [type_map[opt] for opt, _ in type_selections]

        if 'Department' in extension_types:
            note = "Because you selected Call Queue, an additional CSV will be created with enhanced call queue information."
            print(textwrap.fill(note, width=80))
            input("Press Enter to continue...")

        status_selections = pick(
            ['Enabled', 'Disabled', 'Frozen', 'Not Activated', 'Unassigned'],
            'Select (SPACE) extension status(es) to filter for. Press ENTER to confirm:',
            multiselect=True,
            min_selection_count=1,
            indicator='\u25BA\u25BA '
        )
        status_types = [status_map.get(opt, opt) for opt, _ in status_selections]

        query = urlencode({'type': extension_types, 'status': status_types}, doseq=True)
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension?{query}')
        filter_count = resp['paging']['totalElements']

        if filter_count:
            built_url = f'/restapi/v1.0/account/~/extension?perPage={filter_count}&{query}'
            print(f'\n{"#" * 80}')
            print(f'Found {filter_count} extensions with current filters. Proceeding to field selection.')
            print(f'{"#" * 80}\n')
            return filter_count, total_elements, built_url

        print("No extensions matched the current filter parameters. Please try again.\n")
        time.sleep(2)


def audit_checker_specific(client, total_elements):
    """Filter extensions by extension number or email."""
    search_options = ['Extension Number', 'Email']

    while True:
        chosen, _ = pick(search_options, 'Search by:', indicator='\u25BA\u25BA ')

        if chosen == 'Extension Number':
            while True:
                query_ext = input("Enter the Extension Number: ").strip()
                if query_ext.isdigit():
                    break
                print("Please enter a numeric extension number.")
            query = urlencode({'extensionNumber': query_ext}, doseq=True)

        else:  # Email
            query_email = input("Enter the Email Address: ").strip()
            query = urlencode({'email': query_email}, doseq=True)

        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension?{query}')
        filter_count = resp['paging']['totalElements']

        if filter_count:
            built_url = f'/restapi/v1.0/account/~/extension?perPage={filter_count}&{query}'
            print(f'\nFound {filter_count} extension(s). Proceeding to field selection.\n')
            return filter_count, total_elements, built_url

        print("No extensions matched that search. Please try again.\n")
        time.sleep(2)


def prep_user_csv():
    """
    Interactive menu to choose which fields to include in the CSV export.
    Returns a dict of field_name -> bool.
    """
    advisory = (
        "The next window will ask you to select which fields to export to CSV. "
        "Selecting more fields will increase audit time and the chance of hitting "
        "API rate limits. The script will automatically pause if rate limits are reached."
    )
    print(textwrap.fill(advisory, width=80))
    input("Press ENTER to proceed to field selection...")

    field_options = [
        'Default All',
        'ID',
        'Name',
        'Number',
        'Direct Number',
        'Status',
        'Type',
        'Site',
        'Company',
        'Department',
        'Job Title',
        'Email',
        'Administrator Check?',
        'User Assigned Role',
        'Setup Wizard Status',
        'DND State',
        'Business Hours Rule Forwarding',
        'After Hours Rule Forwarding',
        'Device Information',
    ]

    selections = pick(
        field_options,
        'Select (SPACE) fields to export. Press ENTER to confirm:',
        multiselect=True,
        min_selection_count=1,
        indicator='\u25BA\u25BA '
    )
    chosen = {opt for opt, _ in selections}

    use_all = 'Default All' in chosen

    fields = {
        'id':                   use_all or 'ID' in chosen,
        'name':                 use_all or 'Name' in chosen,
        'number':               use_all or 'Number' in chosen,
        'did':                  use_all or 'Direct Number' in chosen,
        'status':               use_all or 'Status' in chosen,
        'type':                 use_all or 'Type' in chosen,
        'site':                 use_all or 'Site' in chosen,
        'company':              use_all or 'Company' in chosen,
        'department':           use_all or 'Department' in chosen,
        'job_title':            use_all or 'Job Title' in chosen,
        'email':                use_all or 'Email' in chosen,
        'admin_check':          use_all or 'Administrator Check?' in chosen,
        'user_assigned_role':   use_all or 'User Assigned Role' in chosen,
        'setup_wizard_status':  use_all or 'Setup Wizard Status' in chosen,
        'dnd_state':            use_all or 'DND State' in chosen,
        'bhr_fw':               use_all or 'Business Hours Rule Forwarding' in chosen,
        'ahr_fw':               use_all or 'After Hours Rule Forwarding' in chosen,
        'device_info':          use_all or 'Device Information' in chosen,
    }

    return fields
