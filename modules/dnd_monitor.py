#!/usr/bin/python

__version__ = "1.0"

import asyncio
import datetime
import textwrap

from pick import pick

from shared.api_utils import fetch_extension_map, rate_limit_get
from shared.csv_utils import append_csv_row
from shared.display_utils import (
    RICH_AVAILABLE, LiveTableDisplay, PlainDisplay, fmt_local,
)
from shared.menu_utils import resolve_extensions
from shared.ws_events import SubscriptionRejected, monitor

MAX_EXTENSION_FILTERS = 20

# The API's dndStatus enum values, with friendlier display labels. The CSV
# keeps the raw enum values so exports stay machine-comparable.
DND_LABELS = {
    'TakeAllCalls':               'Take all calls',
    'DoNotAcceptAnyCalls':        'Do not accept ANY calls',
    'DoNotAcceptDepartmentCalls': 'Do not accept queue calls',
}

DND_STYLES = {
    'TakeAllCalls':               'green',
    'DoNotAcceptAnyCalls':        'bold red',
    'DoNotAcceptDepartmentCalls': 'yellow',
}


def _dnd_label(value):
    return DND_LABELS.get(value, value or '?')


# ──────────────────────────────────────────────────────────────────────────────
# Event handling
# ──────────────────────────────────────────────────────────────────────────────

def _apply_dnd_event(payload, baseline, ext_map):
    """Turn one notification into a row dict, or None when it is not a DND
    change.

    Works for both subscription flavours: the dedicated DND event
    (extension-level, fires only on DND changes) and the Account Presence
    event (account-level, fires on ANY presence change — ringing phones
    included — so the baseline comparison filters it down to DND transitions).
    """
    body = (payload or {}).get('body') or {}
    ext_id = str(body.get('extensionId') or '')
    dnd = body.get('dndStatus')
    if not ext_id or not dnd:
        return None
    previous = baseline.get(ext_id)
    if dnd == previous:
        return None
    baseline[ext_id] = dnd

    ext_number, ext_name = ext_map.get(ext_id, ('', ''))
    return {
        'Event Time':          fmt_local((payload or {}).get('timestamp')),
        'Extension':           ext_number or ext_id,
        'Extension Name':      ext_name,
        'Previous DND Status': previous or '',
        'New DND Status':      dnd,
        'Extension ID':        ext_id,
    }


def _fetch_account_dnd_baseline(client):
    """Current dndStatus for every extension on the account, from the bulk
    account presence endpoint, so the monitor reports transitions rather than
    re-announcing existing states."""
    baseline = {}
    page = 1
    while True:
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/presence?perPage=1000&page={page}')
        if resp is None:
            return baseline
        for rec in resp.get('records', []):
            ext_id = (rec.get('extension') or {}).get('id')
            if ext_id is not None and rec.get('dndStatus'):
                baseline[str(ext_id)] = rec['dndStatus']
        if page >= resp.get('paging', {}).get('totalPages', 1):
            return baseline
        page += 1


def _fetch_extension_dnd_baseline(client, extensions):
    baseline = {}
    for e in extensions:
        resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{e["id"]}/presence')
        if resp and resp.get('dndStatus'):
            baseline[str(e['id'])] = resp['dndStatus']
    return baseline


def _print_baseline(baseline, ext_map):
    """Summarise the starting DND state, listing extensions already in a DND
    mode so a change back to Take-all-calls is understandable later."""
    if not baseline:
        print('Could not read the current DND state — the first event per '
              'extension will show an empty Previous status.')
        return
    counts = {}
    for status in baseline.values():
        counts[status] = counts.get(status, 0) + 1
    summary = ', '.join(f'{n} × {_dnd_label(s)}' for s, n in sorted(counts.items()))
    print(f'Current state of {len(baseline)} extension(s): {summary}')

    in_dnd = [(ext_id, s) for ext_id, s in baseline.items() if s != 'TakeAllCalls']
    if in_dnd:
        print('  Extensions currently in a DND mode:')
        for ext_id, status in in_dnd[:20]:
            number, name = ext_map.get(ext_id, ('', ''))
            print(f'    - ext {number or ext_id:<6} {name:<30} {_dnd_label(status)}')
        if len(in_dnd) > 20:
            print(f'    ...and {len(in_dnd) - 20} more.')


# ──────────────────────────────────────────────────────────────────────────────
# Display specs
# ──────────────────────────────────────────────────────────────────────────────

def _plain_line(r):
    return (
        f"[{r['Event Time']}] "
        f"ext {str(r['Extension'] or '?'):<6} "
        f"{r['Extension Name'] or '':<30} "
        f"{_dnd_label(r['Previous DND Status']) if r['Previous DND Status'] else '(unknown)'}"
        f" → {_dnd_label(r['New DND Status'])}"
    )


TABLE_COLUMNS = [
    ('Time', dict(width=8, no_wrap=True),
     lambda r: r['Event Time'][-8:], None),
    ('Ext', dict(width=6, no_wrap=True),
     lambda r: r['Extension'] or '', None),
    ('Name', dict(ratio=2, no_wrap=True, overflow='ellipsis'),
     lambda r: r['Extension Name'] or '', None),
    ('Previous', dict(ratio=1, no_wrap=True, overflow='ellipsis'),
     lambda r: _dnd_label(r['Previous DND Status']) if r['Previous DND Status'] else '',
     lambda r: 'dim'),
    ('New DND Status', dict(ratio=1, no_wrap=True, overflow='ellipsis'),
     lambda r: _dnd_label(r['New DND Status']),
     lambda r: DND_STYLES.get(r['New DND Status'], '')),
]


# ──────────────────────────────────────────────────────────────────────────────
# Module entry point
# ──────────────────────────────────────────────────────────────────────────────

def run(client):
    """
    Live DND status monitor over a RingCentral WebSocket.
    Read-only: creates an event subscription; no user data is modified.
    """
    try:
        client.authenticate()
    except Exception as e:
        print(f'Token refresh failed: {e}. Proceeding with existing token.')

    print('\n' + '=' * 72)
    print('  DND Status Monitor — Do Not Disturb Changes')
    print('=' * 72)
    print('\n' + textwrap.fill(
        'Reports in real time whenever an extension changes its Do Not '
        'Disturb status (Take all calls / Do not accept ANY calls / Do not '
        'accept queue calls) — useful for tracking queue agents logging in '
        'and out of call acceptance. Account-level monitoring subscribes to '
        'the Account Presence event and reports only DND transitions; '
        'extension-level monitoring uses the dedicated DND status event. '
        'This is read-only. The app registration must have the ReadAccounts, '
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
            f'/restapi/v1.0/account/~/extension/{e["id"]}/presence/dnd'
            for e in extensions
        ]
        numbers = ', '.join(str(e.get('extensionNumber', '?')) for e in extensions[:5])
        if len(extensions) > 5:
            numbers += ', ...'
        subtitle = f'{len(extensions)} extension(s): {numbers}'
        print('\nReading the current DND state of the selected extensions...')
        baseline = _fetch_extension_dnd_baseline(client, extensions)
    else:
        print('Fetching the extension list so events can be labelled with extension numbers...')
        ext_map = fetch_extension_map(client)
        event_filters = ['/restapi/v1.0/account/~/presence']
        subtitle = f'account level ({len(ext_map)} extensions)'
        print('Reading the current DND state of the account...')
        baseline = _fetch_account_dnd_baseline(client)

    _print_baseline(baseline, ext_map)

    # ── CSV logging ──────────────────────────────────────────────────────────
    csv_name = None
    if input('\nLog DND changes to CSV? (y/n, default y): ').strip().lower() != 'n':
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        csv_name = f'DNDMonitor-{date_stamp}.csv'
        print(f'DND changes will be appended to: AuditResults/{csv_name}')

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
            'DND Status Monitor', subtitle,
            f'AuditResults/{csv_name}' if csv_name else '',
            TABLE_COLUMNS, empty_caption='Waiting for DND changes...',
        )
    else:
        display = PlainDisplay(_plain_line)
        print(f'\nMonitoring {subtitle}. Press CTRL+C to stop.\n')

    # ── Monitor ──────────────────────────────────────────────────────────────
    stats = {'changes': 0, 'connections': 0}
    started = datetime.datetime.now()
    rejected = None

    def on_notification(payload):
        row = _apply_dnd_event(payload, baseline, ext_map)
        if row is None:
            return
        stats['changes'] += 1
        display.events([row])
        if csv_name:
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
            'The app registration needs the "Read Accounts" (DND/presence '
            'events), "WebSocket" (the wstoken endpoint — CMN-401) and '
            '"WebSocket Subscriptions" (event delivery) application scopes. '
            'Note that scopes are baked into access tokens when they are '
            'issued and survive refreshes, so a scope added in the developer '
            'console does NOT reach a previously saved login: if the scopes '
            'look right, re-authenticate with --clear-creds (OAuth) or re-run '
            'under JWT, and allow a few minutes for the permission change to '
            'propagate.',
            width=72
        ))

    runtime = (datetime.datetime.now() - started).total_seconds()
    m, s = divmod(int(runtime), 60)
    print(f'\n{"=" * 72}')
    print('  Monitoring stopped.')
    print(f'  Recorded {stats["changes"]} DND change(s) over {m}m {s}s '
          f'across {stats["connections"]} connection(s).')
    if csv_name and stats['changes']:
        print(f'  Changes logged to AuditResults/{csv_name}')
    print('=' * 72)
