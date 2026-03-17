#!/usr/bin/python

__version__ = "1.0"

import json
import re
import textwrap

import requests
from pick import pick

from shared.api_utils import rate_limit_get, rate_limit_post


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_extensions(client):
    """Return list of (display_label, ext_id) for all extensions."""
    resp = rate_limit_get(client, '/restapi/v1.0/account/~/extension?perPage=1000')
    if not resp:
        return []
    return [
        (f"{r.get('extensionNumber', '?')} - {r.get('name', 'Unknown')} [{r.get('type', '')}]", str(r['id']))
        for r in resp.get('records', [])
    ]


def _fetch_company_phone_numbers(client):
    """Return list of (number_string, number_string) for company phone numbers."""
    resp = rate_limit_get(client, '/restapi/v1.0/account/~/phone-number?perPage=1000')
    if not resp:
        return []
    return [
        r.get('phoneNumber')
        for r in resp.get('records', [])
        if r.get('phoneNumber')
    ]


def _validate_e164(number):
    """Return True if number looks like a valid E.164 number."""
    return bool(re.match(r'^\+\d{7,15}$', number))


def _build_caller_conditions():
    """Interactive loop to build a list of caller ID conditions."""
    callers = []
    print("\nEnter caller IDs to match (E.164 format, e.g. +61291234567).")
    while True:
        entry = input(f"  Caller ID #{len(callers) + 1} (or leave blank to finish): ").strip()
        if not entry:
            if not callers:
                print("  No callers entered — skipping caller condition.")
            break
        if not _validate_e164(entry):
            print("  Invalid format. Must start with + followed by 7–15 digits (e.g. +61291234567).")
            continue
        callers.append({'callerId': entry})
        print(f"  Added: {entry}")
    return callers


def _build_weekly_schedule():
    """Interactive builder for a weeklyRanges schedule object."""
    day_map = {
        'Monday': 'monday',
        'Tuesday': 'tuesday',
        'Wednesday': 'wednesday',
        'Thursday': 'thursday',
        'Friday': 'friday',
        'Saturday': 'saturday',
        'Sunday': 'sunday',
    }
    day_selections = pick(
        list(day_map.keys()),
        'Select (SPACE) day(s) for this schedule. Press ENTER to confirm:',
        multiselect=True,
        min_selection_count=1,
        indicator='►► '
    )
    selected_days = [day_map[d] for d, _ in day_selections]

    weekly_ranges = {}
    print("\nFor each day, enter start and end times in 24-hour HH:MM format.")
    for day in selected_days:
        while True:
            start = input(f"  {day.capitalize()} start time (HH:MM): ").strip()
            end = input(f"  {day.capitalize()} end time   (HH:MM): ").strip()
            time_pattern = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
            if time_pattern.match(start) and time_pattern.match(end) and start < end:
                weekly_ranges[day] = [{'from': start, 'to': end}]
                break
            print("  Invalid times. Use HH:MM 24-hour format and ensure start is before end.")

    return {'weeklyRanges': weekly_ranges}


def _build_date_range_schedule():
    """Interactive builder for a specific date/time range."""
    dt_pattern = re.compile(r'^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]) (?:[01]\d|2[0-3]):[0-5]\d$')
    print("\nEnter start and end as YYYY-MM-DD HH:MM (24-hour).")
    while True:
        start = input("  Start datetime: ").strip()
        end = input("  End datetime:   ").strip()
        if dt_pattern.match(start) and dt_pattern.match(end) and start < end:
            return {'ranges': [{'from': start.replace(' ', 'T'), 'to': end.replace(' ', 'T')}]}
        print("  Invalid format or start is not before end. Use YYYY-MM-DD HH:MM.")


def _format_rule_summary(payload, destination_label=None):
    """Return a human-readable summary string of the rule payload."""
    lines = [
        '=' * 72,
        '>>> REVIEW: New Answering Rule',
        '=' * 72,
        f"  Name:    {payload.get('name')}",
        f"  Enabled: {payload.get('enabled')}",
        f"  Type:    {payload.get('type')}",
        f"  Action:  {payload.get('callHandlingAction')}",
    ]
    if destination_label:
        lines.append(f"  Destination: {destination_label}")
    if payload.get('callers'):
        ids = ', '.join(c['callerId'] for c in payload['callers'])
        lines.append(f"  Caller Conditions:  {ids}")
    if payload.get('calledNumbers'):
        nums = ', '.join(n['phoneNumber'] for n in payload['calledNumbers'])
        lines.append(f"  Called Numbers:     {nums}")
    if payload.get('schedule'):
        lines.append(f"  Schedule:           {json.dumps(payload['schedule'])}")
    lines.append('=' * 72)
    return '\n'.join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# View existing rules
# ──────────────────────────────────────────────────────────────────────────────

def _view_existing_rules(client):
    print('\nFetching existing company answering rules...')
    resp = rate_limit_get(client, '/restapi/v1.0/account/~/answering-rule')
    if not resp:
        print('Could not retrieve answering rules.')
        return

    records = resp.get('records', [])
    if not records:
        print('No answering rules found on this account.')
        return

    print(f'\n{"─" * 72}')
    print(f'  {"Name":<30} {"Type":<10} {"Enabled":<8} {"Action"}')
    print(f'{"─" * 72}')
    for rule in records:
        print(
            f"  {rule.get('name', ''):<30} "
            f"{rule.get('type', ''):<10} "
            f"{str(rule.get('enabled', '')):<8} "
            f"{rule.get('callHandlingAction', '')}"
        )
    print(f'{"─" * 72}')
    input('\nPress Enter to continue...')


# ──────────────────────────────────────────────────────────────────────────────
# Create rule
# ──────────────────────────────────────────────────────────────────────────────

def _create_rule(client):
    action_map = {
        'Bypass (route directly to extension, skips IVR greeting)': 'Bypass',
        'Forward Calls (ring extension)':                            'ForwardCalls',
        'Take Messages Only (voicemail)':                            'TakeMessagesOnly',
        'Disconnect':                                                'Disconnect',
        'Play Announcement Only':                                    'PlayAnnouncementOnly',
        'Unconditional Forwarding (external number)':                'UnconditionalForwarding',
    }

    print('\n' + '=' * 72)
    print('  Create New Custom Answering Rule')
    print('=' * 72)

    # Step 1 — Name
    while True:
        name = input('\nEnter a name for the new rule: ').strip()
        if name:
            break
        print('Rule name cannot be empty.')

    # Step 2 — Action
    action_label, _ = pick(
        list(action_map.keys()),
        'Select the call handling action:',
        indicator='►► '
    )
    action = action_map[action_label]

    # Step 3 — Destination
    payload = {
        'name': name,
        'enabled': True,
        'type': 'Custom',
        'callHandlingAction': action,
    }
    destination_label = None

    if action in ('Bypass', 'ForwardCalls'):
        print('\nFetching extensions...')
        extensions = _fetch_extensions(client)
        if not extensions:
            print('Could not fetch extensions. Cannot set a destination.')
            return
        labels = [label for label, _ in extensions]
        chosen_label, chosen_idx = pick(labels, 'Select destination extension:', indicator='►► ')
        ext_id = extensions[chosen_idx][1]
        payload['extension'] = {'id': ext_id}
        destination_label = chosen_label

    elif action == 'UnconditionalForwarding':
        while True:
            number = input('\nEnter the external forwarding number (E.164 format, e.g. +61291234567): ').strip()
            if _validate_e164(number):
                payload['unconditionalForwarding'] = {'phoneNumber': number}
                destination_label = number
                break
            print('Invalid format. Must start with + followed by 7–15 digits.')

    # Step 4 — Caller conditions
    print('\n' + textwrap.fill(
        'Caller conditions restrict this rule to calls FROM specific numbers. '
        'Leave blank to match all callers.',
        width=72
    ))
    ask = input('Add caller conditions? (y/n): ').strip().lower()
    if ask == 'y':
        callers = _build_caller_conditions()
        if callers:
            payload['callers'] = callers

    # Step 5 — Called number conditions
    print('\n' + textwrap.fill(
        'Called number conditions restrict this rule to calls TO specific company numbers.',
        width=72
    ))
    ask = input('Add called number conditions? (y/n): ').strip().lower()
    if ask == 'y':
        print('\nFetching company phone numbers...')
        numbers = _fetch_company_phone_numbers(client)
        if numbers:
            selections = pick(
                numbers,
                'Select (SPACE) numbers to match. Press ENTER to confirm:',
                multiselect=True,
                min_selection_count=1,
                indicator='►► '
            )
            payload['calledNumbers'] = [{'phoneNumber': n} for n, _ in selections]
        else:
            print('Could not retrieve company phone numbers — skipping.')

    # Step 6 — Schedule
    ask = input('\nAdd a schedule to this rule? (y/n): ').strip().lower()
    if ask == 'y':
        sched_choice, _ = pick(
            ['Weekly Schedule (recurring day/time windows)', 'Specific Date/Time Range'],
            'Schedule type:',
            indicator='►► '
        )
        if 'Weekly' in sched_choice:
            payload['schedule'] = _build_weekly_schedule()
        else:
            payload['schedule'] = _build_date_range_schedule()

    # Step 7 — Confirmation gate
    print('\n' + _format_rule_summary(payload, destination_label))
    print('\n>>> RAW JSON PAYLOAD:')
    print(json.dumps(payload, indent=2))
    print()
    print(textwrap.fill(
        'WARNING: This will CREATE a new answering rule on the Auto-Receptionist. '
        'This is a WRITE operation and will immediately affect call routing on a live account.',
        width=72
    ))
    print()
    confirm = input("Type 'CONFIRM' to create this rule, or anything else to cancel: ").strip()
    if confirm != 'CONFIRM':
        print('\nCancelled. No changes were made.')
        return

    # Step 8 — POST
    print('\nCreating rule...')
    try:
        result = rate_limit_post(client, '/restapi/v1.0/account/~/answering-rule', payload)
        print('\n' + '=' * 72)
        print('  Rule created successfully.')
        print('=' * 72)
        print(f"  Rule ID:   {result.get('id')}")
        print(f"  Name:      {result.get('name')}")
        print(f"  Enabled:   {result.get('enabled')}")
        print(f"  Action:    {result.get('callHandlingAction')}")
        print('=' * 72)
    except requests.HTTPError as e:
        print(f'\nFailed to create rule. HTTP {e.response.status_code}')
        try:
            error_body = e.response.json()
            print(f"  Error:   {error_body.get('message', e.response.text)}")
            if e.response.status_code == 403:
                print(
                    '  Note: A 403 typically means the OAuth app lacks the required '
                    'permission scope (EditAccounts or EditCompanyAnsweringRules).'
                )
        except Exception:
            print(f"  Response: {e.response.text}")


# ──────────────────────────────────────────────────────────────────────────────
# Module entry point
# ──────────────────────────────────────────────────────────────────────────────

def run(client):
    """
    Interactive module for viewing and creating Auto-Receptionist answering rules.
    Read operations (viewing) are safe. Create operations POST to the RingCentral API
    and require explicit CONFIRM before executing.
    """
    try:
        client.authenticate()
    except Exception as e:
        print(f'Token refresh failed: {e}. Proceeding with existing token.')

    print('\nAuto-Receptionist Answering Rules')
    print('Note: "Create" operations will modify your live RingCentral account.\n')

    menu_options = [
        'View Existing Answering Rules',
        'Create New Custom Answering Rule',
        'Back to Main Menu',
    ]

    while True:
        chosen, _ = pick(menu_options, 'Select an action:', indicator='►► ')

        if chosen == 'View Existing Answering Rules':
            _view_existing_rules(client)
        elif chosen == 'Create New Custom Answering Rule':
            _create_rule(client)
            input('\nPress Enter to continue...')
        else:
            break
