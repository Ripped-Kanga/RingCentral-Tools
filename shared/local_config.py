"""Configuration handling for the local diagnostics module.

Local diagnostics run without any RingCentral tenancy connection, so every
target (SIP proxies, STUN servers, thresholds) and any SIP credentials come
from a JSON config file rather than the API.

The live config lives at config/local_diagnostics.json and is git-ignored
because it may contain a SIP password. A redacted example is shipped at
config/local_diagnostics.example.json.
"""

import copy
import json
from pathlib import Path


CONFIG_DIR = Path("config")
CONFIG_PATH = CONFIG_DIR / "local_diagnostics.json"
EXAMPLE_PATH = CONFIG_DIR / "local_diagnostics.example.json"


# The proxy list below is a starting point, not an authoritative regional list.
# RingCentral hands each tenancy its own SIP proxy in the sip-provision
# response, and the hostnames differ by region. Any host that does not exist
# will simply report NXDOMAIN in the DNS check — edit the config to match the
# proxies your tenancy actually uses.
DEFAULT_CONFIG = {
    "_comment": [
        "Local diagnostics configuration for RingCentral-Tools.",
        "Edit sip_proxies to match the proxies your tenancy actually uses — the",
        "definitive list for a tenancy comes from GET /restapi/v1.0/client-info/",
        "sip-provision, or from RingCentral's network requirements article for",
        "your region. Hosts that do not resolve are reported as NXDOMAIN.",
        "Set sip_account.enabled to true and fill in the credentials to enable",
        "the SIP OPTIONS and REGISTER tests.",
    ],

    "settings": {
        "latency_samples": 20,
        "sample_interval_ms": 120,
        "timeout_seconds": 3.0,
        "icmp_enabled": True,
        "traceroute_enabled": False,
        "traceroute_max_hops": 20,
        # Most RingCentral handsets are provisioned for unencrypted SIP on TCP
        # 5090, so TLS is off by default — checking it just adds handshake time
        # and reports findings that cannot affect those phones. Set this to true
        # if the site uses encrypted signalling on 5096.
        "check_tls": False,
        "tls_verify": True,
    },

    # VoIP quality thresholds. A measurement at or below "good" passes, at or
    # below "fair" warns, anything higher fails. The latency figures are round
    # trip, so they are double the one-way delay ITU-T G.114 recommends
    # (150ms one way for good quality, 300ms one way before it degrades).
    "thresholds": {
        "latency_ms": {"good": 150.0, "fair": 300.0},
        "jitter_ms":  {"good": 20.0,  "fair": 30.0},
        "loss_pct":   {"good": 1.0,   "fair": 3.0},
    },

    # Confirmed to answer SIP OPTIONS on TCP 5090, which is the unencrypted
    # port RingCentral handsets are normally provisioned for. The tls ports are
    # listed for reference but are only probed when settings.check_tls is true.
    "sip_proxies": [
        {"host": "sip.ringcentral.com",   "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip10.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip11.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip20.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip21.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip30.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip40.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip50.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip60.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip61.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip70.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip71.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip80.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
        {"host": "sip90.ringcentral.com", "udp": [5060], "tcp": [5090], "tls": [5096]},
    ],

    "https_endpoints": [
        "https://platform.ringcentral.com/restapi/v1.0",
        "https://login.ringcentral.com",
        "https://app.ringcentral.com",
    ],

    # Two independently operated STUN servers, so that comparing the public
    # mapping returned by each reveals the NAT's mapping behaviour.
    "stun_servers": [
        {"host": "stun.cloudflare.com", "port": 3478},
        {"host": "stun.l.google.com",   "port": 19302},
    ],

    "sip_account": {
        "enabled": False,
        "_comment": "username is the SIP user (often the DID or extension), "
                    "auth_id is the authorization ID RingCentral issues. If "
                    "auth_id is blank the username is used for digest auth.",
        "username": "",
        "auth_id": "",
        "password": "",
        "domain": "sip.ringcentral.com",
        "outbound_proxy": "",
        "transport": "tls",
        "register_expires": 300,
    },
}


def _deep_merge(base, override):
    """Merge override into a copy of base, recursing into nested dicts.

    Lists are replaced wholesale so that a user pruning sip_proxies down to a
    single host does not get the defaults merged back in.
    """
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def ensure_example_file():
    """Write the shipped example config if it is missing or out of date."""
    CONFIG_DIR.mkdir(exist_ok=True)
    example = copy.deepcopy(DEFAULT_CONFIG)
    example["sip_account"]["username"] = "16135551234"
    example["sip_account"]["auth_id"] = "802345678"
    example["sip_account"]["password"] = "REPLACE_ME"
    payload = json.dumps(example, indent=2) + "\n"
    if not EXAMPLE_PATH.exists() or EXAMPLE_PATH.read_text(encoding="utf-8") != payload:
        EXAMPLE_PATH.write_text(payload, encoding="utf-8")


def load_config(path=None):
    """Load the local diagnostics config, creating it from defaults if absent.

    Returns (config_dict, created) where created is True if the file was just
    written for the first time.
    """
    cfg_path = Path(path) if path else CONFIG_PATH
    ensure_example_file()

    if not cfg_path.exists():
        cfg_path.parent.mkdir(exist_ok=True)
        cfg_path.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n", encoding="utf-8")
        return copy.deepcopy(DEFAULT_CONFIG), True

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"Could not read {cfg_path}: {e}") from e

    # Merge over the defaults so a config written by an older version still
    # picks up newly added keys.
    return _deep_merge(DEFAULT_CONFIG, user_cfg), False


def config_path():
    return CONFIG_PATH


def sip_account_ready(cfg):
    """True if the config holds enough detail to attempt a SIP REGISTER."""
    acct = cfg.get("sip_account", {})
    return bool(
        acct.get("enabled")
        and acct.get("username")
        and acct.get("password")
        and acct.get("domain")
    )
