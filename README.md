# RingCentral-Tools

A modular, CLI-based toolkit for auditing and administering RingCentral instances via the RingCentral REST API. Audit modules are read-only. Administration modules that perform write operations clearly indicate this and require explicit confirmation before making any changes.

---

## Overview

RingCentral-Tools is designed to grow into a full suite of auditing and reporting modules for RingCentral administrators. Each module is self-contained and registered in a central menu, making it easy to add new capabilities over time without touching existing functionality.

On launch the tool presents a menu with two paths:

- **Run Local Diagnostics** — network health checks from the machine you are sitting at. No RingCentral account, OAuth app, or internet-facing credentials required.
- **Connect to a RingCentral Tenancy** — authenticates via OAuth or a JWT credential, verifies connectivity, and presents the module menu below.

Authentication only happens on the tenancy path, so the local diagnostics can be run on a customer site with no RingCentral app credentials to hand.

---

## Local Diagnostics

Runs entirely from the local machine and never contacts the RingCentral API. Intended for answering "is the network at this site fit for VoIP, and can it reach RingCentral?" before or instead of looking at the tenancy.

All checks are read-only, no calls are placed, and nothing is billable.

**Checks available**

| Check | What it proves |
|---|---|
| Latency, Jitter & Packet Loss | TCP connect round-trips to each SIP proxy on each port, plus an ICMP figure where `ping` is available. Reports min/avg/max, jitter and loss against VoIP thresholds. |
| SIP Signalling (OPTIONS) | Sends real SIP `OPTIONS` requests over UDP and TCP (and TLS, if enabled) and measures the signalling round trip. Any final response (including 403/404) proves the path. |
| SIP ALG Detection | Checks whether a firewall SIP ALG is rewriting signalling in flight — the most common cause of one-way audio, failed registration and dropped calls on unencrypted SIP. |
| SIP Registration | Performs a real digest-authenticated `REGISTER` using credentials from the config file, confirming the registrar is reachable and the credentials are valid. |
| DNS Resolution | Resolves every configured SIP, STUN and HTTPS host and times the lookup. |
| NAT Behaviour (STUN) | Queries two independently operated STUN servers from one local UDP port. A mapping that changes per destination means **symmetric NAT** — the most common cause of one-way audio and dropped registrations. |
| TLS Certificates | **Off by default.** Completes the handshake on each SIP TLS port and reports protocol, cipher, issuer, expiry, forward secrecy and SHA-256 fingerprint. Flags POPs that only negotiate legacy crypto. |
| HTTPS Endpoints | Confirms the RingCentral API and app endpoints are reachable and times the round trip. |
| Traceroute | Path to each SIP proxy, via the system `traceroute`/`tracepath`/`tracert`. |
| Local Host & Network | Local IP, gateway, interface MTU, DNS servers in use, and LAN round trip to the gateway. |

**Run Full Local Health Check** runs everything above in one pass and offers to save the whole report as a timestamped text file in `AuditResults/`.

### Reading the results

Every check is graded `[ OK ]`, `[WARN]`, `[FAIL]` or `[SKIP]`. Two grading rules are worth knowing:

- **Jitter and packet loss can fail a path on their own; a high round trip cannot.** A long round trip with clean jitter and zero loss is the signature of a geographically distant proxy, not a broken network, so it is capped at a warning.
- **A SIP TLS certificate that does not chain to a public root is normal.** `sip.ringcentral.com` is signed by RingCentral's own private CA. (The numbered POPs use public EV certificates instead.) The check reports the issuer so that an *unexpected* issuer — which would indicate TLS interception — still stands out.
- **A TLS warning is not a blocked port.** Where a POP only completes the handshake at a lowered OpenSSL security level, the check says so explicitly rather than reporting a connection failure.

Some results are expected and are reported as warnings rather than failures: RingCentral answers `OPTIONS` on TCP and TLS but ignores them on UDP from unregistered sources, so a silent UDP result is not evidence of a blocked port.

### Configuration

On first run a config file is created at `config/local_diagnostics.json`, seeded from `config/local_diagnostics.example.json`. It holds the target lists, the pass/fail thresholds, and optionally a set of SIP credentials. It is git-ignored, because it can contain a SIP password.

```jsonc
{
  "settings":   { "latency_samples": 20, "timeout_seconds": 3.0, "icmp_enabled": true },
  "thresholds": { "latency_ms": {"good": 150.0, "fair": 300.0},
                  "jitter_ms":  {"good": 20.0,  "fair": 30.0},
                  "loss_pct":   {"good": 1.0,   "fair": 3.0} },
  "sip_proxies": [
    {"host": "sip.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]}
  ],
  "sip_account": {
    "enabled":   false,
    "username":  "",
    "auth_id":   "",
    "password":  "",
    "domain":    "sip.ringcentral.com",
    "transport": "tls"
  }
}
```

The shipped proxy list covers `sip` and `sip10/11/20/21/30/40/50/60/61/70/71/80/90.ringcentral.com` — each one verified to answer SIP `OPTIONS` on TCP 5090. (`sip1.ringcentral.com` resolves but does not answer SIP, so it is deliberately absent.)

> **Still confirm the list against your tenancy.** The proxies a tenancy actually uses differ by region and are returned by `GET /restapi/v1.0/client-info/sip-provision`. Hosts that do not exist are reported as NXDOMAIN by the DNS check rather than failing silently.

#### TLS is off by default

RingCentral handsets are normally provisioned for **unencrypted SIP on TCP 5090**. Nothing on 5096 affects those phones, so `settings.check_tls` defaults to `false` — it only adds handshake time and reports findings that cannot apply. Set it to `true` if a site uses encrypted signalling.

The check that matters on 5090 is **SIP ALG Detection**. Because signalling is unencrypted, a firewall ALG can rewrite the addresses inside it as it passes; the check sends an `OPTIONS` request and verifies the `Via` header the proxy echoes back is byte-for-byte what was sent. `received`/`rport` coming back is normal RFC 3581 NAT traversal and is reported as information, not tampering. An ALG cannot read TLS, so this check only applies to UDP and TCP.

When TLS **is** enabled, one thing to expect: every **numbered** POP negotiates Diffie-Hellman parameters below OpenSSL 3.x's default security level, so a modern client refuses the handshake with `DH_KEY_TOO_SMALL`. Only `sip.ringcentral.com` negotiates cleanly (ECDHE, forward secrecy).

This tool retries such handshakes at a lowered security level so the path can still be measured, then reports it as a **warning** with the negotiated cipher — because the port is open and reachable, and the real risk is that softphones on current OS builds may fail TLS against that POP with no firewall involved. Without this handling the check would report a false "TLS blocked".

**Enabling the SIP registration test** — set `sip_account.enabled` to `true` and fill in `username`, `password` and `domain`. `auth_id` is the authorization ID RingCentral issues; leave it blank to use the username. The test registers, confirms the result, then immediately releases the binding with an `Expires: 0` REGISTER so a live handset does not lose its registration.

---

## Tenancy Modules

### User Extension Audit
Performs a comprehensive audit of all extensions on a RingCentral account and exports results to CSV.

**Features:**
- Filter extensions by type (User, Call Queue, IVR Menu, Announcement, Voicemail, etc.), status, extension number, or email
- Select individual fields to export — only the data you need
- Exports a **User/Extension CSV** covering:
  - ID, Name, Extension Number, Direct Number, Status, Type, Site
  - Company, Department, Job Title, Email
  - Administrator status, Assigned Role, Setup Wizard State
  - DND / Presence status
  - Business Hours forwarding destination
  - After Hours forwarding destination
  - Device Name, Model, Serial, and Status
- Exports a **Call Queue CSV** (when Call Queue type is selected) covering:
  - Queue Name and Extension Number
  - Each member's name, extension, and queue acceptance status
  - Hold-time expiration forwarding destination and type
- Writes incrementally — progress is not lost if interrupted
- Automatically respects API rate limits

Results are saved to `AuditResults/` with a datestamp in the filename.

---

### Auto-Receptionist Rules
> **Write module** — can create answering rules on the live account. All write operations require explicit confirmation before executing.

Manages custom answering rules on the company Auto-Receptionist.

**View Existing Rules**
- Lists all current company answering rules with name, type, enabled status, and call handling action

**Create New Custom Rule**
- Interactive step-by-step builder:
  - Rule name
  - Call handling action: Bypass (direct to extension), Forward Calls (ring extension), Take Messages Only, Disconnect, Play Announcement Only, or Unconditional Forwarding (external number)
  - Destination extension (selected from live extension list) or external number
  - Optional caller conditions — restrict the rule to calls from specific numbers
  - Optional called number conditions — restrict to calls arriving on specific company numbers
  - Optional schedule — weekly recurring time windows (e.g. Mon–Fri 09:00–17:00) or a specific date/time range
- Full JSON payload displayed for review before any POST is made
- Requires typing `CONFIRM` (case-sensitive) to proceed — intentionally high-friction for a production write
- API errors (including permission failures) are surfaced with clear messages

**Required OAuth permission scope:** `EditAccounts` or `EditCompanyAnsweringRules`

---

### Tenancy Diagnostics
Read-only troubleshooting tools for a live RingCentral instance. (For network-level checks that need no tenancy, see [Local Diagnostics](#local-diagnostics) above.)

**Handset Registration Poll**
- Polls the registration status of account devices at a user-controlled interval (minimum 10 seconds)
- Watch all device types or a selection (HardPhone, SoftPhone, OtherPhone, WebPhone, Paging, Room)
- Reports every Online ↔ Offline transition as it happens, with device name, model, serial, and extension
- Optionally appends each status change to a timestamped CSV event log, with both the raw `Serial` and a colon-separated `MAC Address` column
- Automatically refreshes the OAuth token during long polling sessions
- Press **CTRL+C** to stop polling and see a session summary

> **On serial numbers and MAC addresses.** RingCentral returns a HardPhone's
> serial as the handset's MAC address in unseparated hex (`48256757A868`). The
> tool prints it colon-separated (`48:25:67:57:A8:68`) so it can be pasted
> straight into a switch ARP table or DHCP lease list, and the CSV exports carry
> both forms. The same `serial` field holds an *endpoint ID* rather than a MAC
> for SoftPhone and mobile clients, and is empty for a HardPhone that has not
> yet been shipped and provisioned — in those cases the value is shown as-is and
> the `MAC Address` column is left blank.

**Device Status Snapshot**
- One-shot report of every device on the account with status counts (Online/Offline)
- Optional CSV export, with both the raw `Serial` and a colon-separated `MAC Address` column

**Call Log Search**
- Search the account call log by date range, direction (Inbound/Outbound), phone number, or extension number
- Optional client-side filter on call result (e.g. Missed, Voicemail, Accepted)
- Results displayed in a table and optionally exported to CSV
- Automatically follows pagination (capped at 10,000 records per search)

**Extension Presence & Device Check**
- Look up a single extension and see its presence status, telephony state, DND status, and all registered devices — useful for diagnosing "calls not ringing" issues

**Required OAuth permission scopes:** `ReadAccounts` (devices/extensions), `ReadCallLog` (call log search), `ReadPresence` (presence check)

---

## Installation

### Clone the repository
```bash
git clone https://github.com/Ripped-Kanga/RingCentral-Tools.git
cd RingCentral-Tools
```

### Install dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

### Optional arguments

| Argument | Description |
|---|---|
| `--client_id` | Provide the application Client ID at runtime |
| `--client_secret` | Provide the application Client Secret at runtime |
| `--auth` | Authentication flow: `oauth` or `jwt`. Defaults to `jwt` when a JWT is supplied, otherwise the tool asks |
| `--jwt` | JWT credential for the JWT flow (prefer `$RINGCENTRAL_JWT` or the hidden prompt) |
| `--clear-creds` | Clear saved credentials and force re-authentication |
| `--local` | Skip the launch menu and go straight to local diagnostics |

If `--client_id` and `--client_secret` are not provided, the tool will prompt for them interactively — but only when the tenancy path is chosen.

### Examples
```bash
# Launch menu (local diagnostics or tenancy)
python main.py

# Straight to local network diagnostics — no credentials needed
python main.py --local

# Tenancy via OAuth browser login
python main.py --auth oauth --client_id YOUR_CLIENT_ID --client_secret YOUR_CLIENT_SECRET

# Tenancy via JWT — the token is read from the environment, never the command line
export RINGCENTRAL_JWT='eyJraWQiOi...'
python main.py --auth jwt --client_id YOUR_CLIENT_ID --client_secret YOUR_CLIENT_SECRET
```

---

## Authentication

Two flows are supported. Both use the same RingCentral app credentials (Client ID and Client Secret) and both hand the modules an identical client, so every module works the same way under either.

### OAuth browser login

The interactive flow. Opens a browser, the operator logs in to RingCentral, and the returned code is exchanged for a token pair. The token pair is cached in `rc_token.json` (gitignored) and refreshed automatically. Use this for your own day-to-day work.

### JWT credential

For giving someone API access **without giving them a RingCentral platform login** — for example handing a customer's IT team or an external tester access to a tenancy for the duration of a project.

A JWT is issued from the RingCentral developer console and grants API access under the permissions of the user who issued it. It carries no console or admin UI access, and it can be revoked from the console at any time without touching any user account.

**Setting one up:**

1. In the [RingCentral developer console](https://developers.ringcentral.com), make sure the app has **JWT auth flow** enabled under its Auth settings, and that its scopes cover the modules to be run (see the per-module scope notes above).
2. Under **Credentials → JWT**, create a JWT scoped to that app, and set an expiry that matches how long access is needed.
3. Give the holder the JWT along with the app's Client ID and Client Secret.

**Running with it:**

```bash
export RINGCENTRAL_JWT='eyJraWQiOi...'
python main.py --auth jwt
```

The JWT is read from `--jwt`, then `$RINGCENTRAL_JWT`, then a hidden interactive prompt. It is **never written to disk** — access tokens are held in memory only and re-minted from the JWT as they expire, so there is no refresh token to manage and nothing left behind on the machine when the tool exits.

Prefer the environment variable or the prompt over `--jwt`; a value passed on the command line is visible in shell history and the process list.

**When access should end:** revoke the JWT in the developer console. Any tokens minted from it stop working within their remaining lifetime (one hour at most), and no new ones can be issued.

---

## Adding New Modules

New modules can be added by:

1. Creating a new file under `modules/` with a `run(client)` function
2. Registering it in the `MODULE_REGISTRY` dict in `main.py`

```python
# main.py
from modules import my_new_module

MODULE_REGISTRY = {
    "User Extension Audit": user_audit,
    "My New Module":        my_new_module,  # add here
}
```

The module will automatically appear in the interactive menu — no other changes required.

Modules in `MODULE_REGISTRY` are handed an authenticated client (OAuth or JWT — both expose the same `authenticate()` / `api_get()` / `api_post()` interface). `local_diagnostics` accepts and ignores that argument, so it can be reached both from the launch menu (with no client) and from the tenancy module menu.

---

## Notes

- To exit at any time, press **CTRL+C**
- Output CSV files are stored in the `AuditResults/` directory
- Selecting more fields during an audit increases runtime and API call volume; the tool will automatically pause if rate limits are hit
- Write modules (e.g. Auto-Receptionist Rules) operate against your **live** RingCentral account — test against a sandbox instance where possible
- Local diagnostics reports are written to `AuditResults/` as timestamped `.txt` files
- `config/local_diagnostics.json` is git-ignored because it can hold a SIP password; commit changes to `config/local_diagnostics.example.json` instead
- Local diagnostics require no extra dependencies — the SIP, STUN and network probes are implemented directly on the Python standard library
