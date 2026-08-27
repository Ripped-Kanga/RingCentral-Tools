"""Minimal SIP client for diagnostics — OPTIONS ping and digest REGISTER.

This is deliberately not a SIP stack. It builds and parses just enough of
RFC 3261 to prove two things from the customer site:

  * the signalling path to a proxy is open and how it performs (OPTIONS)
  * a set of SIP credentials can actually register (REGISTER + RFC 2617 digest)

No media is negotiated and no calls are placed, so nothing here is billable.
UDP, TCP and TLS transports are all supported.
"""

import hashlib
import re
import secrets
import socket
import ssl
import time

from shared.net_checks import is_legacy_crypto_error, relax_security_level, summarise


USER_AGENT = "RingCentral-Tools-Diagnostics/1.0"
MAX_MESSAGE_BYTES = 65535

# SIP over UDP retransmits on timer T1 (RFC 3261 §17.1.1.2). A single retry is
# enough to distinguish a lossy path from a dead one without stalling the menu.
UDP_RETRIES = 2


def _md5(text):
    """MD5 is mandated by RFC 2617 digest auth, not chosen for security."""
    try:
        return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()
    except TypeError:  # Python < 3.9
        return hashlib.md5(text.encode("utf-8")).hexdigest()


def _branch():
    return "z9hG4bK" + secrets.token_hex(8)


def _tag():
    return secrets.token_hex(6)


def _call_id(host):
    return f"{secrets.token_hex(12)}@{host}"


# ──────────────────────────────────────────────────────────────────────────────
# Transport
# ──────────────────────────────────────────────────────────────────────────────

class SipTransport:
    """A single SIP connection over UDP, TCP or TLS."""

    def __init__(self, transport, host, port, timeout=3.0, verify=True):
        self.transport = transport.lower()
        if self.transport not in ("udp", "tcp", "tls"):
            raise ValueError(f"Unsupported SIP transport: {transport}")
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.verify = verify
        self.sock = None
        self.tls_version = None
        self.tls_verified = None
        self.tls_cipher = None
        self.tls_legacy = False
        self._buf = b""

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def open(self):
        if self.transport == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return

        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.transport == "tcp":
            self.sock = raw
            self.sock.settimeout(self.timeout)
            return

        try:
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
            self.tls_verified = True
        except ssl.SSLError as e:
            # Two expected failures here, neither of which means the port is
            # blocked: RingCentral signs SIP certificates with a private CA, and
            # several POPs negotiate crypto that modern OpenSSL rejects by
            # default. Retry unverified — and at a lowered security level when
            # the error says the crypto was the problem — so the signalling test
            # can still run. Both facts are recorded for the report.
            self.tls_legacy = is_legacy_crypto_error(e)
            try:
                raw.close()
            except OSError:
                pass
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if self.tls_legacy:
                relax_security_level(ctx)
            self.sock = ctx.wrap_socket(raw)
            self.tls_verified = False
        self.sock.settimeout(self.timeout)
        self.tls_version = self.sock.version()
        cipher = self.sock.cipher()
        self.tls_cipher = cipher[0] if cipher else None

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def local_addr(self):
        ip, port = self.sock.getsockname()[:2]
        return ip, port

    def send(self, message):
        self.sock.sendall(message.encode("utf-8"))

    def recv(self, timeout=None):
        """Read one complete SIP message, or None on timeout."""
        deadline = time.perf_counter() + (timeout if timeout is not None else self.timeout)
        if self.transport == "udp":
            try:
                self.sock.settimeout(max(0.01, deadline - time.perf_counter()))
                return self.sock.recv(MAX_MESSAGE_BYTES).decode("utf-8", errors="replace")
            except (socket.timeout, OSError):
                return None

        while True:
            message = self._take_message()
            if message is not None:
                return message
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None
            try:
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(MAX_MESSAGE_BYTES)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            self._buf += chunk

    def _take_message(self):
        """Pull one framed message off the stream buffer, honouring Content-Length."""
        split = self._buf.find(b"\r\n\r\n")
        if split == -1:
            return None
        head = self._buf[:split].decode("utf-8", errors="replace")
        match = re.search(r"^(?:Content-Length|l)\s*:\s*(\d+)\s*$", head, re.I | re.M)
        body_len = int(match.group(1)) if match else 0
        total = split + 4 + body_len
        if len(self._buf) < total:
            return None
        message = self._buf[:total].decode("utf-8", errors="replace")
        self._buf = self._buf[total:]
        return message


# ──────────────────────────────────────────────────────────────────────────────
# Message building and parsing
# ──────────────────────────────────────────────────────────────────────────────

def _build(method, request_uri, headers, body=""):
    lines = [f"{method} {request_uri} SIP/2.0"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def parse_status(message):
    """Return (code, reason) from a SIP response, or (None, None)."""
    if not message:
        return None, None
    match = re.match(r"SIP/2\.0\s+(\d{3})\s*(.*)", message.split("\r\n", 1)[0].strip())
    if not match:
        return None, None
    return int(match.group(1)), match.group(2).strip()


def get_header(message, name):
    """First value of a header, case-insensitive."""
    pattern = rf"^{re.escape(name)}\s*:\s*(.*)$"
    match = re.search(pattern, message, re.I | re.M)
    return match.group(1).strip() if match else None


def _response_branch(message):
    via = get_header(message, "Via") or ""
    match = re.search(r"branch=([^;,\s]+)", via)
    return match.group(1) if match else None


def parse_challenge(message):
    """Parse a WWW-Authenticate / Proxy-Authenticate digest challenge."""
    for header in ("WWW-Authenticate", "Proxy-Authenticate"):
        value = get_header(message, header)
        if not value:
            continue
        scheme, _, rest = value.partition(" ")
        if scheme.lower() != "digest":
            continue
        params = {}
        for key, quoted, bare in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', rest):
            params[key.lower()] = quoted if quoted else bare
        params["_header"] = header
        return params
    return None


def build_authorization(challenge, username, password, method, uri):
    """Compute an RFC 2617 digest response (MD5, with or without qop=auth)."""
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop_options = [q.strip() for q in challenge.get("qop", "").split(",") if q.strip()]

    ha1 = _md5(f"{username}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")

    fields = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
    ]

    if "auth" in qop_options:
        cnonce = secrets.token_hex(8)
        nc = "00000001"
        response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        fields.extend([f'response="{response}"', "qop=auth", f"nc={nc}", f'cnonce="{cnonce}"'])
    else:
        response = _md5(f"{ha1}:{nonce}:{ha2}")
        fields.append(f'response="{response}"')

    if challenge.get("opaque"):
        fields.append(f'opaque="{challenge["opaque"]}"')
    fields.append("algorithm=MD5")

    header_name = "Proxy-Authorization" if challenge.get("_header") == "Proxy-Authenticate" else "Authorization"
    return header_name, "Digest " + ", ".join(fields)


# ──────────────────────────────────────────────────────────────────────────────
# OPTIONS ping
# ──────────────────────────────────────────────────────────────────────────────

def options_ping(host, port, transport="udp", domain=None, samples=10,
                 timeout=3.0, interval_ms=200, verify=True):
    """Measure SIP signalling RTT, jitter and loss with OPTIONS requests.

    Any final response counts as reachable — proxies commonly answer an
    unregistered OPTIONS with 403 or 404, which still proves the round trip.
    """
    domain = domain or host
    result = {
        "host": host, "port": port, "transport": transport.lower(),
        "responses": {}, "tls_version": None, "tls_verified": None,
        "tls_cipher": None, "tls_legacy": False, "error": None,
    }

    rtts = []
    try:
        with SipTransport(transport, host, port, timeout=timeout, verify=verify) as conn:
            result["tls_version"] = conn.tls_version
            result["tls_verified"] = conn.tls_verified
            result["tls_cipher"] = conn.tls_cipher
            result["tls_legacy"] = conn.tls_legacy
            local_ip, local_port = conn.local_addr()
            via_transport = conn.transport.upper()

            for i in range(samples):
                branch = _branch()
                call_id = _call_id(local_ip)
                headers = [
                    ("Via", f"SIP/2.0/{via_transport} {local_ip}:{local_port};branch={branch};rport"),
                    ("Max-Forwards", "70"),
                    ("From", f"<sip:diagnostics@{domain}>;tag={_tag()}"),
                    ("To", f"<sip:ping@{domain}>"),
                    ("Call-ID", call_id),
                    ("CSeq", f"{i + 1} OPTIONS"),
                    ("Contact", f"<sip:diagnostics@{local_ip}:{local_port};transport={conn.transport}>"),
                    ("Accept", "application/sdp"),
                    ("User-Agent", USER_AGENT),
                ]
                request = _build("OPTIONS", f"sip:{domain}", headers)

                started = time.perf_counter()
                conn.send(request)
                response = _await_final(conn, branch, timeout)

                if response is None:
                    if i < samples - 1 and interval_ms:
                        time.sleep(interval_ms / 1000.0)
                    continue

                rtts.append((time.perf_counter() - started) * 1000)
                code, reason = parse_status(response)
                key = f"{code} {reason}".strip()
                result["responses"][key] = result["responses"].get(key, 0) + 1

                if i < samples - 1 and interval_ms:
                    time.sleep(interval_ms / 1000.0)

    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, ValueError) as e:
        result["error"] = str(e) or type(e).__name__

    result.update(summarise(rtts, samples))
    return result


def _await_final(conn, branch, timeout):
    """Read until a final response for our branch arrives, or we time out."""
    deadline = time.perf_counter() + timeout
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return None
        message = conn.recv(remaining)
        if message is None:
            return None
        code, _ = parse_status(message)
        if code is None or code < 200:
            continue  # provisional, or a request the proxy sent us; keep waiting
        if branch and _response_branch(message) not in (None, branch):
            continue  # a stray response to an earlier sample
        return message


# ──────────────────────────────────────────────────────────────────────────────
# REGISTER
# ──────────────────────────────────────────────────────────────────────────────

def register(username, password, domain, host=None, port=None, transport="tls",
             auth_id=None, expires=300, timeout=5.0, verify=True, unregister=True):
    """Attempt a digest-authenticated SIP REGISTER.

    Returns a dict describing each leg: the initial request, the challenge, and
    the authenticated retry. By default the registration is immediately
    released with an Expires: 0 REGISTER so the diagnostic does not steal the
    binding from a live handset.
    """
    host = host or domain
    port = int(port) if port else {"udp": 5060, "tcp": 5090, "tls": 5096}[transport.lower()]
    auth_user = auth_id or username

    result = {
        "host": host, "port": port, "transport": transport.lower(), "domain": domain,
        "username": username, "auth_id": auth_user,
        "challenged": False, "realm": None, "authenticated": False,
        "status": None, "reason": None, "rtt_ms": None, "total_ms": None,
        "granted_expires": None, "contact": None, "warning": None,
        "unregistered": None, "tls_version": None, "tls_verified": None,
        "tls_cipher": None, "tls_legacy": False, "error": None,
    }

    started_total = time.perf_counter()
    try:
        with SipTransport(transport, host, port, timeout=timeout, verify=verify) as conn:
            result["tls_version"] = conn.tls_version
            result["tls_verified"] = conn.tls_verified
            result["tls_cipher"] = conn.tls_cipher
            result["tls_legacy"] = conn.tls_legacy
            local_ip, local_port = conn.local_addr()
            via_transport = conn.transport.upper()

            call_id = _call_id(local_ip)
            from_tag = _tag()
            request_uri = f"sip:{domain}"
            aor = f"sip:{username}@{domain}"
            contact = f"<sip:{username}@{local_ip}:{local_port};transport={conn.transport}>"

            def _send_register(cseq, extra_headers=(), expires_value=expires):
                branch = _branch()
                headers = [
                    ("Via", f"SIP/2.0/{via_transport} {local_ip}:{local_port};branch={branch};rport"),
                    ("Max-Forwards", "70"),
                    ("From", f"<{aor}>;tag={from_tag}"),
                    ("To", f"<{aor}>"),
                    ("Call-ID", call_id),
                    ("CSeq", f"{cseq} REGISTER"),
                    ("Contact", contact),
                    ("Expires", str(expires_value)),
                    ("User-Agent", USER_AGENT),
                ]
                headers.extend(extra_headers)
                request = _build("REGISTER", request_uri, headers)
                sent_at = time.perf_counter()
                for _ in range(UDP_RETRIES if conn.transport == "udp" else 1):
                    conn.send(request)
                    response = _await_final(conn, branch, timeout)
                    if response is not None:
                        return response, (time.perf_counter() - sent_at) * 1000
                return None, None

            response, rtt = _send_register(1)
            if response is None:
                result["error"] = "No response to the initial REGISTER (timed out)."
                return result

            code, reason = parse_status(response)
            result.update(status=code, reason=reason, rtt_ms=rtt)

            if code in (401, 407):
                result["challenged"] = True
                challenge = parse_challenge(response)
                if not challenge:
                    result["error"] = f"{code} received but no digest challenge could be parsed."
                    return result
                result["realm"] = challenge.get("realm")

                header_name, header_value = build_authorization(
                    challenge, auth_user, password, "REGISTER", request_uri
                )
                response, rtt = _send_register(2, extra_headers=[(header_name, header_value)])
                if response is None:
                    result["error"] = "No response to the authenticated REGISTER (timed out)."
                    return result
                code, reason = parse_status(response)
                result.update(status=code, reason=reason, rtt_ms=rtt)

            if code == 200:
                result["authenticated"] = True
                result["contact"] = get_header(response, "Contact")
                expires_header = get_header(response, "Expires")
                if expires_header and expires_header.isdigit():
                    result["granted_expires"] = int(expires_header)
                elif result["contact"]:
                    match = re.search(r"expires=(\d+)", result["contact"], re.I)
                    if match:
                        result["granted_expires"] = int(match.group(1))
                if unregister:
                    result["unregistered"] = _release_binding(
                        _send_register, auth_user, password, request_uri
                    )
            else:
                result["warning"] = get_header(response, "Warning")

    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, ValueError, KeyError) as e:
        result["error"] = str(e) or type(e).__name__

    result["total_ms"] = (time.perf_counter() - started_total) * 1000
    return result


def _release_binding(send_register, auth_user, password, request_uri):
    """Send REGISTER with Expires: 0 to drop the binding we just created.

    The registrar issues a fresh nonce for this transaction, so the challenge
    has to be answered again rather than replaying the earlier Authorization.
    """
    response, _ = send_register(3, expires_value=0)
    if response is None:
        return False

    code, _ = parse_status(response)
    if code in (401, 407):
        challenge = parse_challenge(response)
        if not challenge:
            return False
        header_name, header_value = build_authorization(
            challenge, auth_user, password, "REGISTER", request_uri
        )
        response, _ = send_register(4, extra_headers=[(header_name, header_value)], expires_value=0)
        if response is None:
            return False
        code, _ = parse_status(response)

    return code == 200


# ──────────────────────────────────────────────────────────────────────────────
# SIP ALG detection
# ──────────────────────────────────────────────────────────────────────────────

def detect_sip_alg(host, port, transport="tcp", domain=None, timeout=5.0):
    """Detect a firewall SIP ALG rewriting signalling in flight.

    A proxy echoes our Via header back verbatim in its response, adding only
    the ``received`` and ``rport`` parameters that RFC 3581 defines for NAT
    traversal. So if the sent-by address or the branch that comes back is not
    what we sent, something on the path rewrote the packet — almost always a
    SIP ALG on the firewall.

    This only applies to unencrypted signalling: an ALG cannot read or rewrite
    SIP inside TLS, which is why encrypted transports are not tested here.

    ``received``/``rport`` coming back is normal and expected behind NAT, and
    is reported as information rather than tampering.
    """
    domain = domain or host
    result = {
        "host": host, "port": port, "transport": transport.lower(),
        "ok": False, "alg_detected": False, "local_ip": None, "local_port": None,
        "returned_sent_by": None, "received": None, "rport": None,
        "branch_intact": None, "evidence": [], "status": None, "error": None,
    }

    if result["transport"] == "tls":
        result["error"] = "A SIP ALG cannot rewrite encrypted signalling; TLS is not tested."
        return result

    try:
        with SipTransport(transport, host, port, timeout=timeout) as conn:
            local_ip, local_port = conn.local_addr()
            result["local_ip"] = local_ip
            result["local_port"] = local_port
            via_transport = conn.transport.upper()

            branch = _branch()
            headers = [
                ("Via", f"SIP/2.0/{via_transport} {local_ip}:{local_port};branch={branch};rport"),
                ("Max-Forwards", "70"),
                ("From", f"<sip:diagnostics@{domain}>;tag={_tag()}"),
                ("To", f"<sip:ping@{domain}>"),
                ("Call-ID", _call_id(local_ip)),
                ("CSeq", "1 OPTIONS"),
                ("Contact", f"<sip:diagnostics@{local_ip}:{local_port};transport={conn.transport}>"),
                ("User-Agent", USER_AGENT),
            ]
            conn.send(_build("OPTIONS", f"sip:{domain}", headers))

            response = _await_final(conn, None, timeout)
            if response is None:
                result["error"] = "No response to OPTIONS, so the path could not be inspected."
                return result

            result["ok"] = True
            result["status"] = "{} {}".format(*parse_status(response))

            via = get_header(response, "Via") or ""
            sent_by = re.search(r"SIP/2\.0/\w+\s+([^;,\s]+)", via)
            result["returned_sent_by"] = sent_by.group(1) if sent_by else None

            received = re.search(r"received=([^;,\s]+)", via)
            rport = re.search(r"rport=(\d+)", via)
            result["received"] = received.group(1) if received else None
            result["rport"] = int(rport.group(1)) if rport else None

            returned_branch = re.search(r"branch=([^;,\s]+)", via)
            result["branch_intact"] = bool(returned_branch and returned_branch.group(1) == branch)

            evidence = []
            if result["returned_sent_by"]:
                returned_host = result["returned_sent_by"].rsplit(":", 1)[0]
                if returned_host != local_ip:
                    evidence.append(
                        f"Via sent-by came back as {result['returned_sent_by']} but "
                        f"{local_ip}:{local_port} was sent — the address was rewritten in flight."
                    )
            if result["branch_intact"] is False:
                evidence.append("The Via branch parameter was altered in flight.")

            result["evidence"] = evidence
            result["alg_detected"] = bool(evidence)

    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, ValueError) as e:
        result["error"] = str(e) or type(e).__name__

    return result
