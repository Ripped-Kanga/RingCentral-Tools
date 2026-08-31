#!/usr/bin/python

__version__ = "1.0"

import datetime
import textwrap
import time
from urllib.parse import urlencode

from pick import pick

from shared.api_utils import rate_limit_get
from shared.csv_utils import build_csv, append_csv_row


# Access tokens are issued with a 600s TTL (see client_auth/client.py), so
# long-running polls must proactively refresh before expiry.
TOKEN_REFRESH_SECONDS = 480

# The device and call-log endpoints are in RingCentral's "Heavy" usage plan
# (~10 requests/min), so enforce a floor on the polling interval.
MIN_POLL_INTERVAL = 10

DEVICE_TYPE_OPTIONS = ['HardPhone', 'SoftPhone', 'OtherPhone', 'WebPhone', 'Paging', 'Room']


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_all_devices(client):
    """Fetch every device on the account, following pagination.
    Returns a list of device records, or None if the API could not be reached."""
    devices = []
    page = 1
    while True:
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/device?perPage=1000&page={page}')
        if resp is None:
            return devices if devices else None
        devices.extend(resp.get('records', []))
        if page >= resp.get('paging', {}).get('totalPages', 1):
            return devices
        page += 1


def _device_ext_label(device):
    ext = device.get('extension') or {}
    return ext.get('extensionNumber') or ext.get('id') or ''


def _format_mac(serial):
    """Colon-separated form of a serial that is a MAC address, else ''.

    RingCentral returns a HardPhone serial as the handset's MAC in unseparated
    hex (e.g. '48256757A868'), which is awkward to paste into an ARP table or
    DHCP lease list. SoftPhone and mobile records carry an endpoint ID in the
    same field, so anything that is not 12 hex digits is left to the caller.
    """
    raw = str(serial or '').strip().replace(':', '').replace('-', '').replace('.', '')
    if len(raw) != 12 or not set(raw) <= set('0123456789abcdefABCDEF'):
        return ''
    raw = raw.upper()
    return ':'.join(raw[i:i + 2] for i in range(0, 12, 2))


def _device_serial_label(device):
    """The serial in its most useful form: colon-separated when it is a MAC,
    otherwise exactly as the API returned it. '' when there is no serial."""
    serial = str(device.get('serial') or '').strip()
    return _format_mac(serial) or serial


def _device_serial_tag(device):
    """Bracketed serial for inline output, or '' when the API returns none.

    For a HardPhone the serial is the handset's MAC address; for SoftPhone and
    mobile clients it is an endpoint ID instead. A HardPhone serial is only
    returned once the handset has been shipped and provisioned.
    """
    label = _device_serial_label(device)
    return f'[serial {label}] ' if label else ''


def _fmt_local(iso_str):
    """Convert an ISO 8601 UTC timestamp from the API to local time for display."""
    if not iso_str:
        return ''
    try:
        dt = datetime.datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return iso_str


def _fmt_duration(seconds):
    if seconds is None:
        return ''
    m, s = divmod(int(seconds), 60)
    return f'{m}m {s}s' if m else f'{s}s'


def _party_label(party):
    """Format a call log from/to party as 'Name (number)'."""
    if not party:
        return ''
    name = party.get('name') or ''
    number = party.get('phoneNumber') or party.get('extensionNumber') or ''
    if name and number:
        return f'{name} ({number})'
    return name or number


def _print_device_table(devices):
    print(f'\n{"─" * 100}')
    print(f'  {"Name":<28} {"Type":<10} {"Model":<20} {"Ext":<8} {"Serial":<18} {"Status"}')
    print(f'{"─" * 100}')
    for d in devices:
        print(
            f"  {str(d.get('name', ''))[:27]:<28} "
            f"{str(d.get('type', '')):<10} "
            f"{str((d.get('model') or {}).get('name', '')):<20} "
            f"{str(_device_ext_label(d)):<8} "
            f"{_device_serial_label(d):<18} "
            f"{d.get('status', 'Unknown')}"
        )
    print(f'{"─" * 100}')


def _refresh_token_if_due(client, last_refresh):
    """Refresh the OAuth token if it is approaching expiry. Returns the new
    last-refresh timestamp (unchanged if no refresh was needed or it failed)."""
    if time.monotonic() - last_refresh < TOKEN_REFRESH_SECONDS:
        return last_refresh
    try:
        client.authenticate()
        return time.monotonic()
    except Exception as e:
        print(f'  Warning: token refresh failed: {e}. Continuing with existing token.')
        return last_refresh


# ──────────────────────────────────────────────────────────────────────────────
# Handset registration poll
# ──────────────────────────────────────────────────────────────────────────────

def _handset_poll(client):
    print('\n' + '=' * 72)
    print('  Handset Registration Status Poll')
    print('=' * 72)
    print('\n' + textwrap.fill(
        'Polls the registration status of devices on this account at a fixed '
        'interval and reports any devices that go Online or Offline. '
        'The device list endpoint is rate-limited (~10 requests/min), so short '
        'intervals on large accounts may cause automatic rate-limit pauses. '
        'Press CTRL+C at any time to stop polling and return to the menu.',
        width=72
    ))

    while True:
        raw = input(f'\nPoll interval in seconds (minimum {MIN_POLL_INTERVAL}, default 60): ').strip()
        if not raw:
            interval = 60
            break
        if raw.isdigit() and int(raw) >= MIN_POLL_INTERVAL:
            interval = int(raw)
            break
        print(f'Please enter a whole number of seconds >= {MIN_POLL_INTERVAL}.')

    type_selections = pick(
        ['All Types'] + DEVICE_TYPE_OPTIONS,
        'Select (SPACE) device type(s) to watch. Press ENTER to confirm:',
        multiselect=True,
        min_selection_count=1,
        indicator='►► '
    )
    chosen_types = {opt for opt, _ in type_selections}
    watch_all = 'All Types' in chosen_types

    log_changes = input('Log status changes to CSV? (y/n, default y): ').strip().lower() != 'n'
    log_file_name = None
    if log_changes:
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        log_file_name = f'HandsetPoll-{date_stamp}.csv'
        print(f'Status changes will be appended to: AuditResults/{log_file_name}')

    print(f'\nPolling every {interval} seconds. Press CTRL+C to stop.\n')

    baseline = {}
    cycle = 0
    changes_logged = 0
    last_refresh = time.monotonic()
    started = datetime.datetime.now()

    try:
        while True:
            last_refresh = _refresh_token_if_due(client, last_refresh)

            devices = _fetch_all_devices(client)
            now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if devices is None:
                print(f'[{now_str}] Could not retrieve device list. Retrying next cycle...')
                time.sleep(interval)
                continue

            watched = [d for d in devices if watch_all or d.get('type') in chosen_types]
            statuses = {str(d['id']): d for d in watched if 'id' in d}

            online = sum(1 for d in statuses.values() if d.get('status') == 'Online')
            offline = sum(1 for d in statuses.values() if d.get('status') == 'Offline')
            other = len(statuses) - online - offline

            cycle += 1
            summary = f'[{now_str}] Poll #{cycle}: {len(statuses)} devices — {online} Online, {offline} Offline'
            if other:
                summary += f', {other} Other/Unknown'
            print(summary)

            if cycle == 1:
                offline_devices = [d for d in statuses.values() if d.get('status') != 'Online']
                if offline_devices:
                    print('  Devices not currently Online (baseline):')
                    for d in offline_devices[:20]:
                        print(
                            f"    - {d.get('name', 'Unknown')} "
                            f"[ext {_device_ext_label(d)}] "
                            f"{_device_serial_tag(d)}"
                            f"({(d.get('model') or {}).get('name', d.get('type', ''))}) "
                            f"— {d.get('status', 'Unknown')}"
                        )
                    if len(offline_devices) > 20:
                        print(f'    ...and {len(offline_devices) - 20} more.')
            else:
                transitions = []
                for dev_id, d in statuses.items():
                    old = baseline.get(dev_id)
                    new = d.get('status', 'Unknown')
                    if old is not None and old != new:
                        transitions.append((d, old, new))
                for dev_id in baseline:
                    if dev_id not in statuses:
                        print(f'  ! Device {dev_id} no longer appears in the device list.')

                for d, old, new in transitions:
                    marker = '▲' if new == 'Online' else '▼'
                    print(
                        f"  {marker} {d.get('name', 'Unknown')} "
                        f"[ext {_device_ext_label(d)}] "
                        f"{_device_serial_tag(d)}"
                        f"({(d.get('model') or {}).get('name', d.get('type', ''))}) "
                        f"changed: {old} → {new}"
                    )
                    if log_changes:
                        append_csv_row({
                            'Timestamp':       now_str,
                            'Device ID':       str(d.get('id', '')),
                            'Device Name':     d.get('name', ''),
                            'Type':            d.get('type', ''),
                            'Model':           (d.get('model') or {}).get('name', ''),
                            'Serial':          d.get('serial') or '',
                            'MAC Address':     _format_mac(d.get('serial')),
                            'Extension':       _device_ext_label(d),
                            'Previous Status': old,
                            'New Status':      new,
                        }, log_file_name)
                        changes_logged += 1

            baseline = {dev_id: d.get('status', 'Unknown') for dev_id, d in statuses.items()}
            time.sleep(interval)

    except KeyboardInterrupt:
        runtime = (datetime.datetime.now() - started).total_seconds()
        m, s = divmod(int(runtime), 60)
        print(f'\n\n{"=" * 72}')
        print('  Polling stopped.')
        print(f'  Ran {cycle} poll cycle(s) over {m}m {s}s.')
        if log_changes:
            print(f'  {changes_logged} status change(s) logged to AuditResults/{log_file_name}')
        print('=' * 72)


# ──────────────────────────────────────────────────────────────────────────────
# Device status snapshot
# ──────────────────────────────────────────────────────────────────────────────

def _device_snapshot(client):
    print('\nFetching all account devices...')
    devices = _fetch_all_devices(client)
    if devices is None:
        print('Could not retrieve the device list.')
        return
    if not devices:
        print('No devices found on this account.')
        return

    status_counts = {}
    for d in devices:
        status = d.get('status', 'Unknown')
        status_counts[status] = status_counts.get(status, 0) + 1

    print(f'\nFound {len(devices)} devices: ' + ', '.join(f'{v} {k}' for k, v in sorted(status_counts.items())))
    _print_device_table(devices)

    ask = input('\nExport this snapshot to CSV? (y/n): ').strip().lower()
    if ask == 'y':
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        rows = [{
            'Device ID':   str(d.get('id', '')),
            'Device Name': d.get('name', ''),
            'Type':        d.get('type', ''),
            'Model':       (d.get('model') or {}).get('name', ''),
            'Serial':      d.get('serial') or '',
            'MAC Address': _format_mac(d.get('serial')),
            'Extension':   _device_ext_label(d),
            'Site':        (d.get('site') or {}).get('name', ''),
            'Status':      d.get('status', 'Unknown'),
        } for d in devices]
        build_csv(rows, 'DeviceStatusSnapshot', date_stamp)


# ──────────────────────────────────────────────────────────────────────────────
# Call log search
# ──────────────────────────────────────────────────────────────────────────────

def _prompt_datetime(prompt):
    """Prompt for a local date/time, returning an ISO 8601 UTC string or None if
    left blank. Accepts YYYY-MM-DD or YYYY-MM-DD HH:MM."""
    while True:
        raw = input(prompt).strip()
        if not raw:
            return None
        for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                local = datetime.datetime.strptime(raw, fmt)
                utc = local.astimezone(datetime.timezone.utc)
                return utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            except ValueError:
                continue
        print('  Invalid format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM (24-hour), or leave blank.')


def _call_log_search(client):
    print('\n' + '=' * 72)
    print('  Call Log Search')
    print('=' * 72)
    print('\n' + textwrap.fill(
        'Searches the account-level call log. Leave the date fields blank to use '
        'the API default (the last 24 hours). Times are entered in your local '
        'timezone and converted to UTC for the API.',
        width=72
    ))
    print()

    params = {'view': 'Simple', 'perPage': 250}

    date_from = _prompt_datetime('From date (YYYY-MM-DD or YYYY-MM-DD HH:MM, blank for default): ')
    if date_from:
        params['dateFrom'] = date_from
    date_to = _prompt_datetime('To date   (YYYY-MM-DD or YYYY-MM-DD HH:MM, blank for now):     ')
    if date_to:
        params['dateTo'] = date_to

    direction, _ = pick(['All', 'Inbound', 'Outbound'], 'Call direction:', indicator='►► ')
    if direction != 'All':
        params['direction'] = direction

    number_filter, _ = pick(
        ['No number filter', 'Phone Number', 'Extension Number'],
        'Filter by a specific number?',
        indicator='►► '
    )
    if number_filter == 'Phone Number':
        params['phoneNumber'] = input('Enter the phone number (E.164 preferred, e.g. +61291234567): ').strip()
    elif number_filter == 'Extension Number':
        while True:
            ext = input('Enter the extension number: ').strip()
            if ext.isdigit():
                params['extensionNumber'] = ext
                break
            print('Please enter a numeric extension number.')

    print('\nFetching call logs...')
    records = []
    page = 1
    max_pages = 40  # safety cap: 40 pages x 250 = 10,000 records
    while True:
        query = urlencode({**params, 'page': page})
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/call-log?{query}')
        if resp is None:
            if not records:
                print(textwrap.fill(
                    'Could not retrieve call logs. Note: the account call log '
                    'requires the ReadCallLog permission scope on the OAuth app.',
                    width=72
                ))
                return
            break
        records.extend(resp.get('records', []))
        if not resp.get('navigation', {}).get('nextPage'):
            break
        page += 1
        if page > max_pages:
            print(f'Stopped at the {max_pages * 250}-record safety cap. Narrow the date range to see more.')
            break

    if not records:
        print('No call log records matched the search criteria.')
        return

    print(f'Retrieved {len(records)} call log record(s).')

    result_filter = input(
        'Filter by call result text (e.g. Missed, Voicemail, Accepted — blank for all): '
    ).strip().lower()
    if result_filter:
        records = [r for r in records if result_filter in str(r.get('result', '')).lower()]
        print(f'{len(records)} record(s) match result filter "{result_filter}".')
        if not records:
            return

    print(f'\n{"─" * 118}')
    print(f'  {"Start Time":<20} {"Dir":<9} {"From":<30} {"To":<30} {"Result":<16} {"Duration"}')
    print(f'{"─" * 118}')
    for r in records:
        print(
            f"  {_fmt_local(r.get('startTime')):<20} "
            f"{str(r.get('direction', '')):<9} "
            f"{_party_label(r.get('from'))[:29]:<30} "
            f"{_party_label(r.get('to'))[:29]:<30} "
            f"{str(r.get('result', '')):<16} "
            f"{_fmt_duration(r.get('duration'))}"
        )
    print(f'{"─" * 118}')

    ask = input('\nExport these results to CSV? (y/n): ').strip().lower()
    if ask == 'y':
        export_name = input('Enter a name for this export (blank for "CallLogSearch"): ').strip()
        export_name = export_name.replace(' ', '_').replace('/', '-') if export_name else 'CallLogSearch'
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        rows = [{
            'Start Time':     _fmt_local(r.get('startTime')),
            'Direction':      r.get('direction', ''),
            'Type':           r.get('type', ''),
            'Action':         r.get('action', ''),
            'Result':         r.get('result', ''),
            'Duration (s)':   r.get('duration', ''),
            'From Name':      (r.get('from') or {}).get('name', ''),
            'From Number':    (r.get('from') or {}).get('phoneNumber', ''),
            'From Extension': (r.get('from') or {}).get('extensionNumber', ''),
            'To Name':        (r.get('to') or {}).get('name', ''),
            'To Number':      (r.get('to') or {}).get('phoneNumber', ''),
            'To Extension':   (r.get('to') or {}).get('extensionNumber', ''),
            'Session ID':     r.get('sessionId', ''),
        } for r in records]
        build_csv(rows, export_name, date_stamp)


# ──────────────────────────────────────────────────────────────────────────────
# Extension presence check
# ──────────────────────────────────────────────────────────────────────────────

def _presence_check(client):
    print('\n' + '=' * 72)
    print('  Extension Presence & Device Check')
    print('=' * 72)
    print('\n' + textwrap.fill(
        'Looks up a single extension and shows its current presence, telephony '
        'state, DND status, and registered devices — useful for diagnosing '
        '"calls not ringing" issues for a specific user.',
        width=72
    ))

    while True:
        ext_number = input('\nEnter the extension number: ').strip()
        if ext_number.isdigit():
            break
        print('Please enter a numeric extension number.')

    query = urlencode({'extensionNumber': ext_number})
    resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension?{query}')
    ext_records = resp.get('records', []) if resp else []
    if not ext_records:
        print(f'No extension found with number {ext_number}.')
        return

    ext = ext_records[0]
    ext_id = ext['id']

    presence = rate_limit_get(
        client, f'/restapi/v1.0/account/~/extension/{ext_id}/presence?detailedTelephonyState=true'
    )

    print(f'\n{"─" * 72}')
    print(f"  Extension:        {ext.get('extensionNumber', '')} — {ext.get('name', '')}")
    print(f"  Type / Status:    {ext.get('type', '')} / {ext.get('status', '')}")
    if presence:
        print(f"  Presence Status:  {presence.get('presenceStatus', 'N/A')}")
        print(f"  Telephony Status: {presence.get('telephonyStatus', 'N/A')}")
        print(f"  User Status:      {presence.get('userStatus', 'N/A')}")
        print(f"  DND Status:       {presence.get('dndStatus', 'N/A')}")
        if presence.get('message'):
            print(f"  Status Message:   {presence.get('message')}")
    else:
        print('  Presence:         Could not retrieve (may not apply to this extension type).')
    print(f'{"─" * 72}')

    device_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/device')
    devices = device_resp.get('records', []) if device_resp else []
    if devices:
        print(f'\n  {len(devices)} device(s) registered to this extension:')
        _print_device_table(devices)
    else:
        print('\n  No devices registered to this extension.')


# ──────────────────────────────────────────────────────────────────────────────
# Module entry point
# ──────────────────────────────────────────────────────────────────────────────

def run(client):
    """
    Diagnostics module for troubleshooting a RingCentral instance.
    All operations are read-only (GET requests only).
    """
    try:
        client.authenticate()
    except Exception as e:
        print(f'Token refresh failed: {e}. Proceeding with existing token.')

    print('\nDiagnostics')
    print('All diagnostics operations are read-only.\n')

    menu_options = [
        'Handset Registration Poll (interval status monitor)',
        'Device Status Snapshot (one-shot, CSV export)',
        'Call Log Search',
        'Extension Presence & Device Check',
        'Back to Main Menu',
    ]

    while True:
        chosen, _ = pick(menu_options, 'Select a diagnostic:', indicator='►► ')

        if chosen.startswith('Handset Registration Poll'):
            _handset_poll(client)
        elif chosen.startswith('Device Status Snapshot'):
            _device_snapshot(client)
        elif chosen == 'Call Log Search':
            _call_log_search(client)
        elif chosen.startswith('Extension Presence'):
            _presence_check(client)
        else:
            break

        input('\nPress Enter to continue...')
