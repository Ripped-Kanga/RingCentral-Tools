#!/usr/bin/python

__version__ = "1.1"

import asyncio
import datetime
import textwrap

from pick import pick

from shared.api_utils import fetch_extension_map
from shared.csv_utils import append_csv_row
from shared.display_utils import (
    RICH_AVAILABLE, LiveTableDisplay, PlainDisplay, fmt_endpoint, fmt_local,
)
from shared.menu_utils import resolve_extensions
from shared.ws_events import SubscriptionRejected, monitor

# A WebSocket subscription carries all filters in a single request; past this
# many extensions the account-level filter is the better tool anyway.
MAX_EXTENSION_FILTERS = 20

STATUS_STYLES = {
    'Setup':              'cyan',
    'Proceeding':         'yellow',
    'Answered':           'bold green',
    'Hold':               'magenta',
    'Parked':             'blue',
    'Voicemail':          'bright_blue',
    'VoicemailScreening': 'bright_blue',
    'FaxReceive':         'bright_blue',
    'Disconnected':       'red',
    'Gone':               'bright_black',
}


# ──────────────────────────────────────────────────────────────────────────────
# Event rows
# ──────────────────────────────────────────────────────────────────────────────

def _party_rows(payload, ext_map):
    """Flatten one ServerNotification payload into one row dict per party.

    The row is ordered for the CSV header; the display views pick the columns
    they need from the same dict so the CSV and the screen never disagree.
    """
    body = (payload or {}).get('body') or {}
    event_time = fmt_local(body.get('eventTime') or (payload or {}).get('timestamp'))
    origin = (body.get('origin') or {}).get('type', '')

    rows = []
    # A notification with no parties still carries session state worth showing,
    # so fall back to a single empty party rather than dropping it.
    for party in body.get('parties') or [{}]:
        ext_id = str(party.get('extensionId') or '')
        ext_number, ext_name = ext_map.get(ext_id, ('', ''))
        status = party.get('status') or {}
        frm = party.get('from') or {}
        to = party.get('to') or {}
        rows.append({
            'Event Time':           event_time,
            'Status':               status.get('code', ''),
            'Reason':               status.get('reason', ''),
            'Direction':            party.get('direction', ''),
            'Extension':            ext_number or ext_id,
            'Extension Name':       ext_name,
            'From Name':            frm.get('name', ''),
            'From Number':          frm.get('phoneNumber') or frm.get('extensionNumber', ''),
            'To Name':              to.get('name', ''),
            'To Number':            to.get('phoneNumber') or to.get('extensionNumber', ''),
            'Missed Call':          'Yes' if party.get('missedCall') else 'No',
            'Origin':               origin,
            'Telephony Session ID': body.get('telephonySessionId', ''),
            'Party ID':             party.get('id', ''),
            'Extension ID':         ext_id,
            'Sequence':             body.get('sequence', ''),
        })
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Display specs
# ──────────────────────────────────────────────────────────────────────────────

def _plain_line(r):
    line = (
        f"[{r['Event Time']}] "
        f"{r['Status'] or '?':<12} "
        f"{r['Direction'] or '':<9} "
        f"ext {str(r['Extension'] or '?'):<6} "
        f"{fmt_endpoint(r['From Name'], r['From Number'])}"
        f" → {fmt_endpoint(r['To Name'], r['To Number'])}"
    )
    if r['Reason']:
        line += f"  ({r['Reason']})"
    if r['Missed Call'] == 'Yes':
        line += '  [MISSED]'
    return line


TABLE_COLUMNS = [
    ('Time', dict(width=8, no_wrap=True),
     lambda r: r['Event Time'][-8:], None),
    ('Status', dict(width=12, no_wrap=True),
     lambda r: r['Status'] or '?', lambda r: STATUS_STYLES.get(r['Status'], '')),
    ('Dir', dict(width=8, no_wrap=True),
     lambda r: r['Direction'] or '', None),
    ('Ext', dict(width=6, no_wrap=True),
     lambda r: r['Extension'] or '', None),
    ('From', dict(ratio=2, no_wrap=True, overflow='ellipsis'),
     lambda r: fmt_endpoint(r['From Name'], r['From Number']), None),
    ('To', dict(ratio=2, no_wrap=True, overflow='ellipsis'),
     lambda r: fmt_endpoint(r['To Name'], r['To Number']), None),
    ('Reason', dict(ratio=1, no_wrap=True, overflow='ellipsis'),
     lambda r: r['Reason'] or ('Missed' if r['Missed Call'] == 'Yes' else ''), None),
    ('Session', dict(width=10, no_wrap=True),
     lambda r: r['Telephony Session ID'][-8:], None),
]


# ──────────────────────────────────────────────────────────────────────────────
# Module entry point
# ──────────────────────────────────────────────────────────────────────────────

def run(client):
    """
    Live call monitor over a RingCentral WebSocket.
    Read-only: creates an event subscription; no call data is modified.
    """
    try:
        client.authenticate()
    except Exception as e:
        print(f'Token refresh failed: {e}. Proceeding with existing token.')

    print('\n' + '=' * 72)
    print('  Live Call Monitor — Telephony Session Events')
    print('=' * 72)
    print('\n' + textwrap.fill(
        'Streams call events (Setup, Proceeding, Answered, Hold, Parked, '
        'Voicemail, Disconnected) in real time over a RingCentral WebSocket. '
        'This is read-only — it creates an event subscription and never '
        'modifies call data. The app registration must have the CallControl, '
        'WebSocket and WebSocketSubscriptions application permissions. '
        'Press CTRL+C at any time to stop monitoring.',
        width=72
    ))
    print()

    # ── Scope ────────────────────────────────────────────────────────────────
    scope_account = 'Account level — all extensions'
    scope_extension = 'Extension level — specific extensions'
    scope, _ = pick(
        [scope_account, scope_extension, 'Back to module menu'],
        'Select monitoring scope:',
        indicator='►► '
    )
    if scope not in (scope_account, scope_extension):
        return

    if scope == scope_extension:
        extensions = resolve_extensions(client, MAX_EXTENSION_FILTERS)
        if not extensions:
            return
        ext_map = {
            str(e['id']): (e.get('extensionNumber', ''), e.get('name', ''))
            for e in extensions
        }
        event_filters = [
            f'/restapi/v1.0/account/~/extension/{e["id"]}/telephony/sessions'
            for e in extensions
        ]
        numbers = ', '.join(str(e.get('extensionNumber', '?')) for e in extensions[:5])
        if len(extensions) > 5:
            numbers += ', ...'
        subtitle = f'{len(extensions)} extension(s): {numbers}'
    else:
        print('Fetching the extension list so events can be labelled with extension numbers...')
        ext_map = fetch_extension_map(client)
        event_filters = ['/restapi/v1.0/account/~/telephony/sessions']
        subtitle = f'account level ({len(ext_map)} extensions)'

    # ── Direction filter ─────────────────────────────────────────────────────
    direction, _ = pick(['All', 'Inbound', 'Outbound'], 'Call direction to monitor:', indicator='►► ')
    if direction != 'All':
        event_filters = [f'{f}?direction={direction}' for f in event_filters]

    # ── CSV logging ──────────────────────────────────────────────────────────
    csv_name = None
    if input('Log all events to CSV? (y/n, default y): ').strip().lower() != 'n':
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        csv_name = f'CallMonitor-{date_stamp}.csv'
        print(f'Events will be appended to: AuditResults/{csv_name}')

    # ── View ─────────────────────────────────────────────────────────────────
    table_view = 'Live table view (updates in place)'
    plain_view = 'Plain scrolling log (better for capture/tmux)'
    if RICH_AVAILABLE:
        view, _ = pick([table_view, plain_view], 'Select display view:', indicator='►► ')
    else:
        print("The 'rich' package is not installed — using the plain scrolling log.")
        view = plain_view

    if view == table_view:
        display = LiveTableDisplay(
            'Live Call Monitor', subtitle,
            f'AuditResults/{csv_name}' if csv_name else '',
            TABLE_COLUMNS, empty_caption='Waiting for call events...',
        )
    else:
        display = PlainDisplay(_plain_line)
        print(f'\nMonitoring {subtitle}. Press CTRL+C to stop.\n')

    # ── Monitor ──────────────────────────────────────────────────────────────
    stats = {'notifications': 0, 'rows': 0, 'connections': 0}
    started = datetime.datetime.now()
    rejected = None

    def on_notification(payload):
        stats['notifications'] += 1
        rows = _party_rows(payload, ext_map)
        stats['rows'] += len(rows)
        display.events(rows)
        if csv_name:
            for row in rows:
                append_csv_row(row, csv_name)

    def on_connect():
        stats['connections'] += 1

    display.start()
    try:
        asyncio.run(monitor(client, event_filters, display, on_notification, on_connect))
    except KeyboardInterrupt:
        pass
    except SubscriptionRejected as e:
        rejected = e
    finally:
        display.stop()

    if rejected:
        print(f'\nThe subscription was refused and monitoring cannot continue:\n  {rejected}\n')
        print(textwrap.fill(
            'The app registration needs the "Call Control" (telephony session '
            'events — its absence raises SUB-410), "WebSocket" (the wstoken '
            'endpoint — CMN-401) and "WebSocket Subscriptions" (event '
            'delivery) application scopes. Note that scopes are baked into '
            'access tokens when they are issued and survive refreshes, so a '
            'scope added in the developer console does NOT reach a previously '
            'saved login: if the scopes look right, re-authenticate with '
            '--clear-creds (OAuth) or re-run under JWT, and allow a few '
            'minutes for the permission change to propagate.',
            width=72
        ))

    runtime = (datetime.datetime.now() - started).total_seconds()
    m, s = divmod(int(runtime), 60)
    print(f'\n{"=" * 72}')
    print('  Monitoring stopped.')
    print(f'  Received {stats["notifications"]} notification(s) '
          f'({stats["rows"]} party event(s)) over {m}m {s}s '
          f'across {stats["connections"]} connection(s).')
    if csv_name and stats['rows']:
        print(f'  Events logged to AuditResults/{csv_name}')
    print('=' * 72)
