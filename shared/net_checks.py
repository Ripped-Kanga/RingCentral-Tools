"""Local network health checks for VoIP readiness.

Everything here is standard library only and runs unprivileged. Latency is
measured with TCP connect round-trips rather than raw ICMP sockets (which need
root on Linux); the system ping binary is used opportunistically for a true
ICMP figure when it is available.
"""

import hashlib
import platform
import re
import secrets
import socket
import ssl
import statistics
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


DEFAULT_TIMEOUT = 3.0

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020


# ──────────────────────────────────────────────────────────────────────────────
# Statistics
# ──────────────────────────────────────────────────────────────────────────────

def summarise(samples_ms, attempted):
    """Reduce a list of RTT samples to the figures that matter for VoIP.

    Jitter is the mean absolute difference between successive samples, which is
    the same quantity RFC 3550 tracks for RTP streams.
    """
    received = len(samples_ms)
    result = {
        "attempted": attempted,
        "received": received,
        "loss_pct": 100.0 * (attempted - received) / attempted if attempted else 100.0,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "jitter_ms": None,
        "stdev_ms": None,
    }
    if not received:
        return result

    result["min_ms"] = min(samples_ms)
    result["avg_ms"] = sum(samples_ms) / received
    result["max_ms"] = max(samples_ms)
    result["stdev_ms"] = statistics.pstdev(samples_ms) if received > 1 else 0.0

    if received > 1:
        deltas = [abs(samples_ms[i] - samples_ms[i - 1]) for i in range(1, received)]
        result["jitter_ms"] = sum(deltas) / len(deltas)
    else:
        result["jitter_ms"] = 0.0

    return result


def classify(value, good, fair):
    """Grade a measurement against two thresholds. Lower is better."""
    if value is None:
        return "FAIL"
    if value <= good:
        return "OK"
    if value <= fair:
        return "WARN"
    return "FAIL"


def worst(*verdicts):
    order = {"OK": 0, "WARN": 1, "FAIL": 2, "SKIP": -1}
    real = [v for v in verdicts if v in order and v != "SKIP"]
    if not real:
        return "SKIP"
    return max(real, key=lambda v: order[v])


# ──────────────────────────────────────────────────────────────────────────────
# DNS
# ──────────────────────────────────────────────────────────────────────────────

def resolve(host):
    """Resolve a hostname, timing the lookup.

    Returns {host, ips, ms, error}. getaddrinfo does not honour socket
    timeouts, so this blocks for as long as the system resolver does.
    """
    started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return {"host": host, "ips": [], "ms": (time.perf_counter() - started) * 1000, "error": str(e)}

    elapsed = (time.perf_counter() - started) * 1000
    ips = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return {"host": host, "ips": ips, "ms": elapsed, "error": None}


def local_resolvers():
    """Best-effort list of the DNS servers this machine is configured to use."""
    system = platform.system()
    servers = []
    try:
        if system in ("Linux", "Darwin"):
            resolv = Path("/etc/resolv.conf")
            if resolv.exists():
                for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1:
                            servers.append(parts[1])
            # systemd-resolved stubs everything at 127.0.0.53; ask it for the real ones.
            if servers in ([], ["127.0.0.53"]):
                out = _run(["resolvectl", "dns"], timeout=3)
                if out:
                    servers = re.findall(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{6,})", out) or servers
        elif system == "Windows":
            out = _run(["nslookup", "."], timeout=5) or ""
            servers = re.findall(r"Address(?:es)?:\s*([0-9a-fA-F\.:]+)", out)
    except Exception:
        pass
    # De-duplicate while preserving order.
    seen = set()
    return [s for s in servers if not (s in seen or seen.add(s))]


# ──────────────────────────────────────────────────────────────────────────────
# Latency / reachability
# ──────────────────────────────────────────────────────────────────────────────

def tcp_probe(host, port, samples=10, timeout=DEFAULT_TIMEOUT, interval_ms=120):
    """Measure TCP connect round-trip time to host:port.

    The time to complete the handshake approximates a network round trip, and
    unlike ICMP it also proves the port itself is reachable through firewalls.
    """
    rtts = []
    last_error = None
    for i in range(samples):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((host, port))
            rtts.append((time.perf_counter() - started) * 1000)
        except (socket.timeout, OSError) as e:
            last_error = str(e)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        if i < samples - 1 and interval_ms:
            time.sleep(interval_ms / 1000.0)

    result = summarise(rtts, samples)
    result["host"] = host
    result["port"] = port
    result["error"] = last_error if not rtts else None
    return result


def _run(cmd, timeout=30):
    """Run a system command, returning combined output or None if unavailable."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="ignore",
        )
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def icmp_ping(host, count=10, timeout=DEFAULT_TIMEOUT):
    """Run the system ping binary and parse its summary.

    Returns None when ping is unavailable or its output could not be parsed;
    callers fall back to the TCP figures in that case.
    """
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    elif system == "Darwin":
        cmd = ["ping", "-n", "-c", str(count), "-W", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-n", "-c", str(count), "-W", str(max(1, int(timeout))), host]

    out = _run(cmd, timeout=count * timeout + 15)
    if out is None:
        return None

    result = {"host": host, "attempted": count, "raw": out}

    loss = re.search(r"([\d\.]+)%\s*(?:packet )?loss", out)
    result["loss_pct"] = float(loss.group(1)) if loss else None

    unix = re.search(
        r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)(?:/([\d\.]+))?\s*ms", out
    )
    if unix:
        result["min_ms"] = float(unix.group(1))
        result["avg_ms"] = float(unix.group(2))
        result["max_ms"] = float(unix.group(3))
        result["stdev_ms"] = float(unix.group(4)) if unix.group(4) else None
        return result

    win_min = re.search(r"Minimum\s*=\s*(\d+)ms", out)
    win_max = re.search(r"Maximum\s*=\s*(\d+)ms", out)
    win_avg = re.search(r"Average\s*=\s*(\d+)ms", out)
    if win_min and win_max and win_avg:
        result["min_ms"] = float(win_min.group(1))
        result["max_ms"] = float(win_max.group(1))
        result["avg_ms"] = float(win_avg.group(1))
        result["stdev_ms"] = None
        return result

    if result["loss_pct"] is not None:
        result["min_ms"] = result["avg_ms"] = result["max_ms"] = result["stdev_ms"] = None
        return result
    return None


def traceroute(host, max_hops=20, timeout=60):
    """Run the system traceroute/tracert, returning its raw output."""
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]

    out = _run(cmd, timeout=timeout)
    if out is None and system not in ("Windows",):
        # traceroute is often absent on minimal installs; tracepath needs no setuid.
        out = _run(["tracepath", "-n", "-m", str(max_hops), host], timeout=timeout)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# TLS
# ──────────────────────────────────────────────────────────────────────────────

# OpenSSL 3.x security level 2 rejects the Diffie-Hellman parameters and
# legacy renegotiation that several RingCentral SIP POPs still negotiate.
# Dropping to level 1 lets the handshake complete so the path can be measured
# and the weak crypto reported, rather than looking like a blocked port.
LEGACY_CIPHERS = "DEFAULT:@SECLEVEL=1"

LEGACY_CRYPTO_ERRORS = (
    "DH_KEY_TOO_SMALL",
    "UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
    "UNSUPPORTED_PROTOCOL",
    "NO_CIPHERS_AVAILABLE",
    "EE_KEY_TOO_SMALL",
    "CA_MD_TOO_WEAK",
)


def is_legacy_crypto_error(error):
    """True if the handshake failed because our OpenSSL refuses weak crypto,
    rather than because the far end is unreachable."""
    text = str(error).upper()
    return any(marker in text for marker in LEGACY_CRYPTO_ERRORS)


def relax_security_level(ctx):
    """Permit the legacy crypto modern OpenSSL disables by default."""
    try:
        ctx.set_ciphers(LEGACY_CIPHERS)
    except ssl.SSLError:
        pass
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    return ctx


def tls_probe(host, port, timeout=DEFAULT_TIMEOUT, verify=True):
    """Complete a TLS handshake and report the negotiated parameters.

    Two RingCentral-specific behaviours are handled so they do not read as
    faults when they are not:

      * Certificates are signed by a private RingCentral CA, so they never
        chain to a public root. On verification failure the presented
        certificate is re-used as its own trust anchor for a second handshake,
        purely so subject/issuer/expiry can still be reported.
      * Several POPs negotiate Diffie-Hellman parameters below OpenSSL 3.x's
        default security level. Those are retried at a lowered security level
        and flagged as legacy crypto, which is a real finding rather than a
        connectivity problem.
    """
    result = {
        "host": host, "port": port, "ok": False, "verified": False,
        "protocol": None, "cipher": None, "subject": None, "issuer": None,
        "not_after": None, "days_left": None, "handshake_ms": None,
        "fingerprint": None, "self_signed_ca": False, "legacy_crypto": False,
        "forward_secrecy": None, "error": None,
    }

    def _handshake(ctx):
        started = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                elapsed = (time.perf_counter() - started) * 1000
                return elapsed, tls.version(), tls.cipher(), tls.getpeercert()

    def _record(elapsed, version, cipher, verified):
        result.update(ok=True, verified=verified, handshake_ms=elapsed, protocol=version)
        if cipher:
            result["cipher"] = cipher[0]
            # ECDHE/DHE key exchange is what provides forward secrecy.
            result["forward_secrecy"] = cipher[0].startswith(("ECDHE", "DHE", "TLS_"))

    # 1. The normal case: verify against the public trust store.
    try:
        elapsed, version, cipher, cert = _handshake(ssl.create_default_context())
        _record(elapsed, version, cipher, verified=True)
        _fill_cert(result, cert)
        return result
    except ssl.SSLError as e:
        result["error"] = str(e)
        legacy = is_legacy_crypto_error(e)
    except (socket.timeout, OSError) as e:
        result["error"] = str(e)
        return result

    if legacy:
        result["legacy_crypto"] = True

    # 2. Pin the certificate the server presents so its details can be read.
    try:
        pem = _server_certificate(host, port, timeout, legacy)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
            # Allow the leaf itself to terminate the chain.
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx.load_verify_locations(cadata=pem)
        if legacy:
            relax_security_level(ctx)

        elapsed, version, cipher, cert = _handshake(ctx)
        _record(elapsed, version, cipher, verified=False)
        result["fingerprint"] = _fingerprint(pem)
        _fill_cert(result, cert)
        return result
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        pass

    # 3. Last resort: prove the handshake completes even if nothing about the
    #    certificate can be read.
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if legacy:
            relax_security_level(ctx)
        elapsed, version, cipher, _ = _handshake(ctx)
        _record(elapsed, version, cipher, verified=False)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        result["error"] = f'{result["error"] or ""} / {e}'.strip(" /")
    return result


def _server_certificate(host, port, timeout, legacy=False):
    """Fetch the peer certificate as PEM without validating it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if legacy:
        relax_security_level(ctx)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("peer presented no certificate")
    return ssl.DER_cert_to_PEM_cert(der)


def _fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def _fill_cert(result, cert):
    if not cert:
        return

    def _flatten(field):
        return ", ".join(f"{k}={v}" for rdn in cert.get(field, ()) for k, v in rdn)

    result["subject"] = _flatten("subject")
    result["issuer"] = _flatten("issuer")

    subject_org = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
    issuer_org = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    result["self_signed_ca"] = (
        bool(subject_org.get("organizationName"))
        and subject_org.get("organizationName") == issuer_org.get("organizationName")
    )

    not_after = cert.get("notAfter")
    if not_after:
        result["not_after"] = not_after
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["days_left"] = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# HTTPS endpoints
# ──────────────────────────────────────────────────────────────────────────────

def http_probe(url, timeout=DEFAULT_TIMEOUT):
    """Time an HTTPS GET. Any HTTP status counts as reachable — a 401 from an
    authenticated endpoint still proves the path through the firewall works."""
    started = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        return {
            "url": url,
            "ok": True,
            "status": resp.status_code,
            "ms": (time.perf_counter() - started) * 1000,
            "error": None,
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "ok": False,
            "status": None,
            "ms": (time.perf_counter() - started) * 1000,
            "error": type(e).__name__ + ": " + str(e).split("\n")[0][:120],
        }


# ──────────────────────────────────────────────────────────────────────────────
# STUN / NAT behaviour
# ──────────────────────────────────────────────────────────────────────────────

def _stun_request(sock, host, port, timeout):
    """Send one RFC 5389 Binding Request and parse the mapped address."""
    txn_id = secrets.token_bytes(12)
    packet = struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, txn_id)

    sock.settimeout(timeout)
    started = time.perf_counter()
    sock.sendto(packet, (host, port))

    deadline = started + timeout
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise socket.timeout("no STUN response")
        sock.settimeout(remaining)
        data, _ = sock.recvfrom(2048)
        if len(data) < 20:
            continue
        msg_type, msg_len, cookie, resp_txn = struct.unpack("!HHI12s", data[:20])
        if resp_txn != txn_id or cookie != STUN_MAGIC_COOKIE:
            continue
        rtt = (time.perf_counter() - started) * 1000
        if msg_type != STUN_BINDING_SUCCESS:
            raise OSError(f"STUN error response type 0x{msg_type:04x}")
        return _parse_stun_attributes(data[20:20 + msg_len], txn_id) + (rtt,)


def _parse_stun_attributes(body, txn_id):
    """Return (mapped_ip, mapped_port) from a Binding Success Response body."""
    offset = 0
    mapped = (None, None)
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack("!HH", body[offset:offset + 4])
        value = body[offset + 4:offset + 4 + attr_len]
        offset += 4 + attr_len + ((4 - attr_len % 4) % 4)  # attributes are 4-byte aligned

        if attr_type in (STUN_ATTR_XOR_MAPPED_ADDRESS, STUN_ATTR_MAPPED_ADDRESS) and len(value) >= 8:
            family = value[1]
            if family != 0x01:  # IPv4 only
                continue
            port = struct.unpack("!H", value[2:4])[0]
            addr = value[4:8]
            if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS:
                port ^= (STUN_MAGIC_COOKIE >> 16) & 0xFFFF
                addr = bytes(b ^ c for b, c in zip(addr, struct.pack("!I", STUN_MAGIC_COOKIE)))
            candidate = (socket.inet_ntoa(addr), port)
            # Prefer XOR-MAPPED-ADDRESS when both are present.
            if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS or mapped == (None, None):
                mapped = candidate
    return mapped


def stun_probe(servers, timeout=DEFAULT_TIMEOUT):
    """Discover the public mapping for a single local UDP port.

    Querying two servers from the same local socket reveals the NAT's mapping
    behaviour (RFC 4787). If the public port changes per destination the NAT is
    symmetric, which breaks SIP unless the far end supports a media relay.
    """
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    local_port = sock.getsockname()[1]

    try:
        for server in servers:
            host = server.get("host") if isinstance(server, dict) else str(server)
            port = int(server.get("port", 3478)) if isinstance(server, dict) else 3478
            entry = {"server": f"{host}:{port}", "ok": False,
                     "mapped_ip": None, "mapped_port": None, "rtt_ms": None, "error": None}
            try:
                mapped_ip, mapped_port, rtt = _stun_request(sock, host, port, timeout)
                if mapped_ip is None:
                    entry["error"] = "response contained no IPv4 mapped address"
                else:
                    entry.update(ok=True, mapped_ip=mapped_ip, mapped_port=mapped_port, rtt_ms=rtt)
            except (socket.timeout, socket.gaierror, OSError, struct.error) as e:
                entry["error"] = str(e) or type(e).__name__
            results.append(entry)
    finally:
        sock.close()

    return {"local_port": local_port, "results": results, "mapping": _mapping_verdict(results, local_port)}


def _mapping_verdict(results, local_port):
    successes = [r for r in results if r["ok"]]
    if not successes:
        return {"behaviour": "Unknown", "verdict": "WARN",
                "detail": "No STUN server responded — UDP to port 3478 may be blocked."}

    ports = {r["mapped_port"] for r in successes}
    ips = {r["mapped_ip"] for r in successes}

    if len(successes) == 1:
        return {"behaviour": "Indeterminate", "verdict": "WARN",
                "detail": "Only one STUN server responded; NAT mapping behaviour could not be compared."}
    if len(ports) > 1 or len(ips) > 1:
        return {"behaviour": "Symmetric NAT", "verdict": "FAIL",
                "detail": "The public mapping changed per destination. Symmetric NAT commonly "
                          "causes one-way audio and failed registrations on SIP."}
    public_port = next(iter(ports))
    if public_port == local_port:
        return {"behaviour": "Endpoint-independent (full cone / no NAT)", "verdict": "OK",
                "detail": "The public port matches the local port and is stable across destinations."}
    return {"behaviour": "Endpoint-independent mapping (cone NAT)", "verdict": "OK",
            "detail": "The public mapping is stable across destinations, which SIP handles well."}


# ──────────────────────────────────────────────────────────────────────────────
# Local host information
# ──────────────────────────────────────────────────────────────────────────────

def primary_local_ip():
    """The source address this host would use to reach the internet.

    Uses a connectionless UDP socket, so no packets are actually sent.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_gateway():
    system = platform.system()
    try:
        if system == "Linux":
            out = _run(["ip", "route", "show", "default"], timeout=5)
            if out:
                match = re.search(r"default via (\S+)(?: dev (\S+))?", out)
                if match:
                    return match.group(1), match.group(2)
        elif system == "Darwin":
            out = _run(["route", "-n", "get", "default"], timeout=5)
            if out:
                gw = re.search(r"gateway:\s*(\S+)", out)
                dev = re.search(r"interface:\s*(\S+)", out)
                if gw:
                    return gw.group(1), dev.group(1) if dev else None
        elif system == "Windows":
            out = _run(["ipconfig"], timeout=10)
            if out:
                match = re.search(r"Default Gateway[^\n:]*:\s*([0-9\.]+)", out)
                if match:
                    return match.group(1), None
    except Exception:
        pass
    return None, None


def interface_mtu(interface):
    if not interface or platform.system() != "Linux":
        return None
    try:
        return int(Path(f"/sys/class/net/{interface}/mtu").read_text().strip())
    except (OSError, ValueError):
        return None


def local_network_info():
    gateway, interface = default_gateway()
    return {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "local_ip": primary_local_ip(),
        "gateway": gateway,
        "interface": interface,
        "mtu": interface_mtu(interface),
        "resolvers": local_resolvers(),
    }
