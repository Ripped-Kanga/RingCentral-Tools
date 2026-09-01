"""RingCentral WebSocket event subscription plumbing (the WSG protocol).

Used by the live monitor modules: exchange the API access token for a
single-use WebSocket token, connect, create the subscription, and dispatch
incoming notifications to a module-supplied handler, reconnecting forever.
"""

import asyncio
import json
import uuid

import requests
import websockets

WS_TOKEN_ENDPOINT = '/restapi/oauth/wstoken'

# The server idle-timeouts a quiet connection after 30 minutes, and not every
# network path passes protocol-level ping frames through untouched, so an
# application-level Heartbeat message is sent whenever the socket has been
# silent for this long.
RECV_TIMEOUT_SECONDS = 60

# Reconnect backoff bounds. The server forcibly disconnects every client once
# per 24 hours (absolute timeout), so reconnecting is part of normal operation,
# not just error recovery.
BACKOFF_INITIAL_SECONDS = 2
BACKOFF_MAX_SECONDS = 60


class SubscriptionRejected(Exception):
    """Raised when the server refuses the subscription (or the wstoken request)
    for a reason that will not improve with retrying, e.g. a missing app
    permission. Bubbles out of the reconnect loop to abort the session."""


def error_text(body, status):
    """Human-readable form of a WebSocket error body + status."""
    if isinstance(body, dict):
        code = body.get('errorCode', '')
        message = body.get('message', '')
        if not message:
            message = '; '.join(
                e.get('message', '') for e in (body.get('errors') or []) if e.get('message')
            )
        text = ' '.join(str(p) for p in (status, code, message) if p)
        return text or str(body)
    return f'status {status}'


def ws_endpoint(client):
    """Exchange the API access token for a single-use WebSocket token and
    server URI (POST /restapi/oauth/wstoken)."""
    for attempt in (1, 2):
        headers = {'Authorization': f'Bearer {client.get_access_token()}'}
        resp = requests.post(f'{client.api_base_url}{WS_TOKEN_ENDPOINT}', headers=headers)
        if resp.status_code == 401 and attempt == 1:
            # The OAuth flow's 600s access token can expire between reconnects;
            # refresh once and retry before treating the failure as permanent.
            client.authenticate()
            continue
        if 400 <= resp.status_code < 500:
            raise SubscriptionRejected(
                f'WebSocket token request refused (HTTP {resp.status_code}): {resp.text[:300]}'
            )
        resp.raise_for_status()
        data = resp.json()
        return data['uri'], data['ws_access_token']


def parse_message(raw):
    """A WebSocket message is a two-element JSON array: [meta, body]."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}, {}
    if not isinstance(data, list) or not data:
        return {}, {}
    meta = data[0] if isinstance(data[0], dict) else {}
    body = data[1] if len(data) > 1 else {}
    return meta, body


async def _recv_message(ws, timeout):
    return parse_message(await asyncio.wait_for(ws.recv(), timeout=timeout))


async def _subscribe(ws, event_filters):
    """Consume the ConnectionDetails greeting, then create the subscription.

    A WebSocket server holds exactly one subscription, carrying every filter in
    one request, and renews it automatically — no refresh handling is needed.
    """
    meta, body = await _recv_message(ws, timeout=15)
    if meta.get('type') == 'ConnectionDetails' and (meta.get('status') or 200) >= 400:
        raise SubscriptionRejected(f'Connection refused: {error_text(body, meta.get("status"))}')

    request_id = str(uuid.uuid4())
    await ws.send(json.dumps([
        {
            'type': 'ClientRequest',
            'messageId': request_id,
            'method': 'POST',
            'path': '/restapi/v1.0/subscription',
        },
        {
            'eventFilters': event_filters,
            'deliveryMode': {'transportType': 'WebSocket'},
        },
    ]))

    # The reply echoes our messageId; anything else that arrives first
    # (heartbeats etc.) is skipped rather than treated as the answer.
    for _ in range(10):
        meta, body = await _recv_message(ws, timeout=15)
        if meta.get('messageId') != request_id:
            continue
        status = meta.get('status') or 0
        if status >= 400:
            raise SubscriptionRejected(error_text(body, status))
        return
    raise ConnectionResetError('No response to the subscription request.')


async def _receive_loop(ws, on_notification):
    """Dispatch incoming messages until the connection drops."""
    while True:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_SECONDS)
        except TimeoutError:
            await ws.send(json.dumps([{'type': 'Heartbeat', 'messageId': str(uuid.uuid4())}]))
            continue

        meta, body = parse_message(raw)
        mtype = meta.get('type')

        if mtype == 'ServerNotification':
            on_notification(body)
        elif mtype == 'Heartbeat':
            continue  # echo of our own keep-alive
        elif mtype == 'Error' or (meta.get('status') or 0) >= 400:
            # Includes WSG-902/903 idle and absolute timeouts, which the docs
            # say to answer by reconnecting.
            raise ConnectionResetError(error_text(body, meta.get('status')))


async def monitor(client, event_filters, display, on_notification, on_connect=None):
    """Connect / subscribe / receive, reconnecting with backoff forever.

    `display` needs a .status(text) method; `on_notification(payload)` is
    called once per ServerNotification with the notification JSON;
    `on_connect()` is called after each successful subscription.

    Session recovery via the wsc token is deliberately not used: subscriptions
    take one round-trip to recreate, which is simpler and covers every
    disconnect cause the same way.
    """
    backoff = BACKOFF_INITIAL_SECONDS
    while True:
        try:
            display.status('Requesting WebSocket endpoint...')
            uri, token = ws_endpoint(client)
            display.status('Connecting...')
            async with websockets.connect(f'{uri}?access_token={token}') as ws:
                await _subscribe(ws, event_filters)
                if on_connect:
                    on_connect()
                backoff = BACKOFF_INITIAL_SECONDS
                display.status(
                    f'● Connected — subscribed to {len(event_filters)} event filter(s)'
                )
                await _receive_loop(ws, on_notification)
        except SubscriptionRejected:
            raise
        except (websockets.exceptions.WebSocketException, OSError,
                requests.RequestException) as e:
            reason = str(e) or e.__class__.__name__
            display.status(f'○ Connection lost ({reason}). Reconnecting in {backoff}s...')
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX_SECONDS)
