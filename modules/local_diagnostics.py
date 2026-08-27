#!/usr/bin/python

__version__ = "1.0"
__purpose__ = "Run network health checks from the local machine without connecting to a RingCentral tenancy."

import datetime
import textwrap

from pick import pick

from shared import local_config, net_checks, sip_probe
from shared.csv_utils import AUDIT_DIR, ensure_audit_dir


WIDTH = 78

MARKERS = {
    "OK":   "[ OK ]",
    "WARN": "[WARN]",
    "FAIL": "[FAIL]",
    "SKIP": "[SKIP]",
    "INFO": "[ -- ]",
}


# ──────────────────────────────────────────────────────────────────────────────
# Report collection
# ──────────────────────────────────────────────────────────────────────────────

class Report:
    """Prints as it goes and buffers the same output for optional export."""

    def __init__(self, title):
        self.lines = []
        self.counts = {"OK": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
        self.started = datetime.datetime.now()
        self.line("=" * WIDTH)
        self.line(f"  {title}")
        self.line(f"  {self.started.strftime('%Y-%m-%d %H:%M:%S')}")
        self.line("=" * WIDTH)

    def line(self, text=""):
        print(text)
        self.lines.append(text)

    def blank(self):
        self.line("")

    def heading(self, text):
        self.blank()
        self.line("─" * WIDTH)
        self.line(f"  {text}")
        self.line("─" * WIDTH)

    def item(self, verdict, label, detail=""):
        self.counts[verdict] = self.counts.get(verdict, 0) + 1
        marker = MARKERS.get(verdict, MARKERS["INFO"])
        self.line(f"  {marker}  {label}")
        if detail:
            for chunk in str(detail).split("\n"):
                self.line(f"           {chunk}")

    def note(self, text):
        for chunk in textwrap.wrap(text, width=WIDTH - 4):
            self.line(f"  {chunk}")

    def summary(self):
        elapsed = (datetime.datetime.now() - self.started).total_seconds()
        self.blank()
        self.line("=" * WIDTH)
        self.line(
            f"  Summary: {self.counts['OK']} passed, {self.counts['WARN']} warning(s), "
            f"{self.counts['FAIL']} failure(s), {self.counts['SKIP']} skipped"
        )
        self.line(f"  Completed in {elapsed:.1f}s")
        self.line("=" * WIDTH)

    def offer_export(self, default_name="LocalDiagnostics"):
        ask = input("\nSave this report to a text file? (y/n): ").strip().lower()
        if ask != "y":
            return None
        ensure_audit_dir()
        stamp = self.started.strftime("%Y-%m-%d_%H-%M")
        path = AUDIT_DIR / f"{default_name}-{stamp}.txt"
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        print(f"Report written to: {path}")
        return path


# ──────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ms(value):
    return f"{value:.1f}ms" if value is not None else "n/a"


def _pct(value):
    return f"{value:.1f}%" if value is not None else "n/a"


DISTANT_PROXY_NOTE = (
    "Round trip is high but jitter and loss are clean. That is the signature of a "
    "geographically distant proxy rather than a network fault — confirm this is a "
    "proxy your tenancy actually uses before treating it as a problem."
)


def _grade_path(avg_ms, jitter_ms, loss_pct, thresholds):
    """Grade a network path for voice, returning (verdict, note).

    Jitter and packet loss are what actually break a call, so they alone can
    fail a path. A high round trip on an otherwise clean path is capped at a
    warning: it usually means the proxy is far away, not that the link is bad.
    """
    latency = net_checks.classify(avg_ms, thresholds["latency_ms"]["good"], thresholds["latency_ms"]["fair"])
    jitter = (
        net_checks.classify(jitter_ms, thresholds["jitter_ms"]["good"], thresholds["jitter_ms"]["fair"])
        if jitter_ms is not None else "OK"
    )
    loss = (
        net_checks.classify(loss_pct, thresholds["loss_pct"]["good"], thresholds["loss_pct"]["fair"])
        if loss_pct is not None else "OK"
    )

    if jitter == "FAIL" or loss == "FAIL":
        return "FAIL", None
    if latency == "FAIL" and jitter == "OK" and loss == "OK":
        return "WARN", DISTANT_PROXY_NOTE
    return net_checks.worst(latency, jitter, loss), None


def _grade_stats(stats, thresholds):
    """Grade a summarise() result. Returns (verdict, note)."""
    if not stats["received"]:
        return "FAIL", None
    return _grade_path(stats["avg_ms"], stats["jitter_ms"], stats["loss_pct"], thresholds)


def _stats_detail(stats):
    return (
        f"min {_ms(stats['min_ms'])}  avg {_ms(stats['avg_ms'])}  max {_ms(stats['max_ms'])}  "
        f"jitter {_ms(stats['jitter_ms'])}  loss {_pct(stats['loss_pct'])} "
        f"({stats['received']}/{stats['attempted']})"
    )


def _select_proxies(cfg, prompt="Select (SPACE) SIP proxies to test. Press ENTER to confirm:"):
    """Let the user narrow the configured proxy list. Returns a list of dicts."""
    proxies = cfg.get("sip_proxies", [])
    if not proxies:
        print("No SIP proxies are configured. Edit " + str(local_config.config_path()) + ".")
        return []
    if len(proxies) == 1:
        return proxies

    options = ["All configured proxies"] + [p["host"] for p in proxies]
    selections = pick(options, prompt, multiselect=True, min_selection_count=1, indicator="►► ")
    chosen = {opt for opt, _ in selections}
    if "All configured proxies" in chosen:
        return proxies
    return [p for p in proxies if p["host"] in chosen]


# ──────────────────────────────────────────────────────────────────────────────
# Individual checks
# ──────────────────────────────────────────────────────────────────────────────

def check_local_info(cfg, report):
    report.heading("Local Host & Network")
    info = net_checks.local_network_info()

    report.item("INFO", f"Hostname:  {info['hostname']}  ({info['platform']})")
    report.item(
        "OK" if info["local_ip"] else "WARN",
        f"Local IP:  {info['local_ip'] or 'could not be determined'}",
        f"Interface: {info['interface'] or 'unknown'}"
        + (f"   MTU: {info['mtu']}" if info["mtu"] else ""),
    )

    if info["gateway"]:
        gw_ping = net_checks.icmp_ping(info["gateway"], count=4, timeout=2.0)
        detail = (
            f"LAN round trip: avg {_ms(gw_ping.get('avg_ms'))}, loss {_pct(gw_ping.get('loss_pct'))}"
            if gw_ping else
            "ICMP unavailable — install or allow ping for a LAN latency figure."
        )
        report.item("INFO", f"Gateway:   {info['gateway']}", detail)
    else:
        report.item("WARN", "Gateway:   could not be determined")

    if info["resolvers"]:
        report.item("INFO", "DNS servers in use", ", ".join(info["resolvers"]))
    else:
        report.item("WARN", "DNS servers could not be determined")

    if info["mtu"] and info["mtu"] < 1500:
        report.item(
            "WARN",
            f"Interface MTU is {info['mtu']} (below the 1500 Ethernet default)",
            "A reduced MTU is normal on PPPoE/VPN links but can fragment large "
            "SIP INVITEs over UDP. Prefer TCP or TLS signalling on such links.",
        )


def check_dns(cfg, report):
    report.heading("DNS Resolution")
    hosts = [p["host"] for p in cfg.get("sip_proxies", [])]
    hosts += [s["host"] if isinstance(s, dict) else str(s) for s in cfg.get("stun_servers", [])]
    for url in cfg.get("https_endpoints", []):
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            hosts.append(host)

    seen = set()
    for host in [h for h in hosts if not (h in seen or seen.add(h))]:
        res = net_checks.resolve(host)
        if res["error"]:
            report.item("FAIL", f"{host}", f"Resolution failed: {res['error']}")
        else:
            verdict = "WARN" if res["ms"] > 500 else "OK"
            report.item(
                verdict,
                f"{host}  →  {', '.join(res['ips'][:4])}"
                + (f" (+{len(res['ips']) - 4} more)" if len(res["ips"]) > 4 else ""),
                f"Lookup took {_ms(res['ms'])}" + ("  — slow resolver" if verdict == "WARN" else ""),
            )


def check_latency(cfg, report, proxies=None):
    report.heading("Latency, Jitter & Packet Loss to SIP Proxies")
    settings = cfg["settings"]
    thresholds = cfg["thresholds"]
    proxies = proxies if proxies is not None else cfg.get("sip_proxies", [])

    if not proxies:
        report.item("SKIP", "No SIP proxies configured")
        return

    report.note(
        f"TCP connect round-trips are used for latency ({settings['latency_samples']} samples "
        f"per port). Pass thresholds: round trip ≤{thresholds['latency_ms']['good']:.0f}ms, "
        f"jitter ≤{thresholds['jitter_ms']['good']:.0f}ms, loss ≤{thresholds['loss_pct']['good']:.1f}%. "
        "Jitter and loss are what break a call, so they alone can fail a path; a high "
        "round trip on an otherwise clean path is only ever a warning."
    )
    report.blank()

    for proxy in proxies:
        host = proxy["host"]

        if settings.get("icmp_enabled", True):
            ping = net_checks.icmp_ping(host, count=min(10, settings["latency_samples"]),
                                        timeout=settings["timeout_seconds"])
            if ping is None:
                report.item("SKIP", f"{host} — ICMP", "ping is unavailable or blocked on this host.")
            elif ping.get("avg_ms") is None:
                report.item("FAIL", f"{host} — ICMP", f"100% loss ({_pct(ping.get('loss_pct'))}). "
                                                      "ICMP is often filtered and may not indicate a real fault.")
            else:
                # ICMP gives no jitter figure of its own; mdev stands in for it.
                verdict, note = _grade_path(
                    ping["avg_ms"], ping.get("stdev_ms"), ping.get("loss_pct"), thresholds
                )
                detail = (
                    f"min {_ms(ping['min_ms'])}  avg {_ms(ping['avg_ms'])}  max {_ms(ping['max_ms'])}  "
                    f"mdev {_ms(ping.get('stdev_ms'))}  loss {_pct(ping.get('loss_pct'))}"
                )
                report.item(verdict, f"{host} — ICMP", detail + (f"\n{note}" if note else ""))

        transports = ("tcp", "tls") if settings.get("check_tls", False) else ("tcp",)
        for transport in transports:
            for port in proxy.get(transport, []):
                stats = net_checks.tcp_probe(
                    host, port,
                    samples=settings["latency_samples"],
                    timeout=settings["timeout_seconds"],
                    interval_ms=settings["sample_interval_ms"],
                )
                label = f"{host}:{port} — SIP over {transport.upper()}"
                if not stats["received"]:
                    report.item("FAIL", label, f"No connection established. {stats['error'] or ''}".strip())
                else:
                    verdict, note = _grade_stats(stats, thresholds)
                    report.item(verdict, label, _stats_detail(stats) + (f"\n{note}" if note else ""))

        if proxy.get("udp"):
            ports = ", ".join(str(p) for p in proxy["udp"])
            report.item(
                "INFO", f"{host}:{ports} — SIP over UDP",
                "UDP reachability cannot be proven by a connect test. Run the SIP "
                "Signalling Test to measure the UDP path with OPTIONS requests.",
            )
        report.blank()


def check_tls(cfg, report, proxies=None):
    report.heading("TLS Handshake & Certificates")
    settings = cfg["settings"]
    proxies = proxies if proxies is not None else cfg.get("sip_proxies", [])

    if not settings.get("check_tls", False):
        report.item(
            "SKIP", "TLS checks are disabled",
            "Handsets provisioned for unencrypted SIP on TCP 5090 are unaffected by "
            "anything on 5096. Set settings.check_tls to true in "
            f"{local_config.config_path()} if this site uses encrypted signalling.",
        )
        return

    tested = False

    for proxy in proxies:
        for port in proxy.get("tls", []):
            tested = True
            res = net_checks.tls_probe(proxy["host"], port,
                                       timeout=settings["timeout_seconds"],
                                       verify=settings.get("tls_verify", True))
            label = f"{proxy['host']}:{port}"
            if not res["ok"]:
                report.item("FAIL", label, f"Handshake failed: {res['error']}")
                continue

            detail = f"{res['protocol']}  {res['cipher']}  handshake {_ms(res['handshake_ms'])}"
            if res["forward_secrecy"] is False:
                detail += "  (no forward secrecy)"
            if res["not_after"]:
                detail += f"\nCertificate expires {res['not_after']}"
                if res["days_left"] is not None:
                    detail += f" ({res['days_left']} days)"
            if res["subject"]:
                detail += f"\nSubject: {res['subject']}"

            if res["fingerprint"]:
                detail += f"\nSHA-256: {res['fingerprint']}"

            if res["legacy_crypto"]:
                # The handshake only succeeded after lowering OpenSSL's security
                # level, so softphones on current OS builds may fail against
                # this POP even though the port is plainly open.
                report.item(
                    "WARN", label,
                    detail + "\nThis POP negotiates crypto that OpenSSL 3.x rejects at its "
                    "default security level, so the handshake only completed after lowering "
                    "it. The port is open and reachable — but clients on current OS builds "
                    "may fail TLS here without any firewall being involved. Worth raising "
                    "with RingCentral, and worth preferring a POP that negotiates cleanly.",
                )
                continue

            if not res["verified"] and res["self_signed_ca"]:
                # RingCentral signs its SIP certificates with a private CA that is
                # not in any public trust store. Expected, so not a failure — but
                # the issuer is worth showing so an intercepting proxy stands out.
                report.item(
                    "OK", label,
                    detail + "\nSigned by the operator's own private CA, which is normal for "
                    "SIP TLS and is why it does not chain to a public root. Check the issuer "
                    "above matches the carrier — an unexpected issuer would indicate TLS "
                    "interception.",
                )
            elif not res["verified"]:
                report.item(
                    "WARN", label,
                    detail + f"\nCertificate did not verify: {res['error']}"
                    "\nThe issuer does not match the certificate subject's organisation. "
                    "Confirm this is the carrier's certificate and not an intercepting proxy.",
                )
            elif res["days_left"] is not None and res["days_left"] < 30:
                report.item("WARN", label, detail + "\nCertificate expires within 30 days.")
            else:
                report.item("OK", label, detail)

    if not tested:
        report.item("SKIP", "No TLS ports configured on any SIP proxy")


def check_https(cfg, report):
    report.heading("HTTPS Endpoints")
    settings = cfg["settings"]
    endpoints = cfg.get("https_endpoints", [])
    if not endpoints:
        report.item("SKIP", "No HTTPS endpoints configured")
        return

    for url in endpoints:
        res = net_checks.http_probe(url, timeout=settings["timeout_seconds"])
        if not res["ok"]:
            report.item("FAIL", url, res["error"])
        else:
            # Any status proves the path is open; only the round trip is graded.
            verdict = "WARN" if res["ms"] > 1500 else "OK"
            report.item(verdict, f"{url}  →  HTTP {res['status']}", f"Round trip {_ms(res['ms'])}")


def check_stun(cfg, report):
    report.heading("NAT Behaviour (STUN)")
    servers = cfg.get("stun_servers", [])
    if not servers:
        report.item("SKIP", "No STUN servers configured")
        return

    report.note(
        "Two STUN servers are queried from the same local UDP port. If the public "
        "mapping differs between them the NAT is symmetric, which is the most common "
        "cause of one-way audio and dropped registrations on SIP."
    )
    report.blank()

    probe = net_checks.stun_probe(servers, timeout=cfg["settings"]["timeout_seconds"])
    for entry in probe["results"]:
        if entry["ok"]:
            report.item(
                "OK", f"{entry['server']}",
                f"Public mapping {entry['mapped_ip']}:{entry['mapped_port']}  "
                f"(local port {probe['local_port']})  RTT {_ms(entry['rtt_ms'])}",
            )
        else:
            report.item("WARN", f"{entry['server']}", f"No usable response: {entry['error']}")

    mapping = probe["mapping"]
    report.blank()
    report.item(mapping["verdict"], f"NAT mapping behaviour: {mapping['behaviour']}", mapping["detail"])


def check_sip_signalling(cfg, report, proxies=None):
    report.heading("SIP Signalling (OPTIONS)")
    settings = cfg["settings"]
    thresholds = cfg["thresholds"]
    proxies = proxies if proxies is not None else cfg.get("sip_proxies", [])

    if not proxies:
        report.item("SKIP", "No SIP proxies configured")
        return

    report.note(
        "OPTIONS requests are sent on each configured transport. Any final response "
        "counts as reachable — proxies commonly answer an unregistered OPTIONS with "
        "403 or 404, which still proves the signalling round trip. RingCentral "
        "answers on TCP and TLS but ignores OPTIONS on UDP from unregistered "
        "sources, so a silent UDP result is expected and is reported as a warning "
        "rather than a failure."
    )
    report.blank()

    samples = max(5, min(settings["latency_samples"], 20))
    transports = ("udp", "tcp", "tls") if settings.get("check_tls", False) else ("udp", "tcp")
    for proxy in proxies:
        host = proxy["host"]
        for transport in transports:
            for port in proxy.get(transport, []):
                res = sip_probe.options_ping(
                    host, port, transport=transport,
                    domain=cfg["sip_account"].get("domain") or host,
                    samples=samples,
                    timeout=settings["timeout_seconds"],
                    interval_ms=settings["sample_interval_ms"],
                    verify=settings.get("tls_verify", True),
                )
                label = f"{host}:{port}/{transport.upper()}"

                if res["error"] and not res["received"]:
                    # The transport itself never came up — refused, filtered or unresolvable.
                    report.item("FAIL", label, f"Could not establish {transport.upper()}: {res['error']}")
                    continue
                if not res["received"]:
                    # A silent proxy is not proof of a fault. RingCentral answers
                    # OPTIONS on TCP and TLS but ignores them on UDP from
                    # unregistered sources, so this is expected on UDP 5060.
                    if transport == "udp":
                        detail = (
                            f"No reply to {res['attempted']} OPTIONS requests. UDP has no "
                            "handshake, so this cannot distinguish a filtered path from a "
                            "proxy that ignores unregistered OPTIONS — RingCentral proxies "
                            "do the latter. Treat the TCP/TLS results as the reachability "
                            "verdict and use this only to compare against a working site."
                        )
                    else:
                        detail = (
                            f"The {transport.upper()} connection was established, so the port "
                            f"is open, but the proxy did not answer {res['attempted']} OPTIONS "
                            "requests. Signalling reachability is proven; the proxy is simply "
                            "not responding to unauthenticated requests."
                        )
                    report.item("WARN", label, detail)
                    continue

                detail = _stats_detail(res)
                if res["responses"]:
                    detail += "\nResponses: " + ", ".join(
                        f"{count}× {status}" for status, count in sorted(res["responses"].items())
                    )
                if res["tls_version"]:
                    detail += f"\nTLS: {res['tls_version']}"
                    if res.get("tls_cipher"):
                        detail += f" / {res['tls_cipher']}"
                    if res.get("tls_legacy"):
                        # Verification never ran — the handshake itself was
                        # rejected until the security level was lowered, so no
                        # claim can be made about the certificate chain here.
                        detail += ("\nHandshake required lowering OpenSSL's security level — "
                                   "see the TLS section.")
                    elif res["tls_verified"] is False:
                        detail += " (not chained to a public root — see the TLS section)"
                verdict, note = _grade_stats(res, thresholds)
                report.item(verdict, label, detail + (f"\n{note}" if note else ""))
        report.blank()


def check_sip_register(cfg, report):
    report.heading("SIP Registration")
    account = cfg.get("sip_account", {})

    if not local_config.sip_account_ready(cfg):
        report.item(
            "SKIP", "No SIP credentials configured",
            f"Set sip_account.enabled to true and fill in username, password and "
            f"domain in {local_config.config_path()} to enable this test.",
        )
        return

    transport = account.get("transport", "tls").lower()
    host, port = _register_target(account, transport)

    report.note(
        f"Registering {account['username']}@{account['domain']} via {host}:{port} over "
        f"{transport.upper()}. The binding is released immediately afterwards with an "
        "Expires: 0 REGISTER so a live handset does not lose its registration."
    )
    report.blank()

    res = sip_probe.register(
        username=account["username"],
        password=account["password"],
        domain=account["domain"],
        host=host,
        port=port,
        transport=transport,
        auth_id=account.get("auth_id") or None,
        expires=int(account.get("register_expires", 300)),
        timeout=max(5.0, cfg["settings"]["timeout_seconds"]),
        verify=cfg["settings"].get("tls_verify", True),
    )

    if res["error"] and res["status"] is None:
        report.item("FAIL", f"REGISTER to {host}:{port}/{transport.upper()}", res["error"])
        return

    if res["challenged"]:
        report.item("INFO", f"Challenged by realm \"{res['realm']}\"", "Digest credentials were computed and resent.")
    else:
        report.item("WARN", "The registrar did not issue a digest challenge",
                    "The credentials were therefore not verified by this test.")

    status_label = f"{res['status']} {res['reason']}".strip()
    if res["authenticated"]:
        detail = f"Round trip {_ms(res['rtt_ms'])}  (total {_ms(res['total_ms'])})"
        if res["granted_expires"] is not None:
            detail += f"\nRegistrar granted Expires: {res['granted_expires']}s"
        if res["contact"]:
            detail += f"\nContact: {res['contact']}"
        report.item("OK", f"REGISTER → {status_label}", detail)
        report.item(
            "OK" if res["unregistered"] else "WARN",
            "Test registration released" if res["unregistered"] else
            "Test registration may still be active",
            "" if res["unregistered"] else
            f"The Expires: 0 REGISTER was not confirmed. The binding will expire on its own "
            f"after up to {res['granted_expires'] or account.get('register_expires', 300)}s.",
        )
    elif res["status"] in (401, 403, 407):
        report.item(
            "FAIL", f"REGISTER → {status_label}",
            "The registrar rejected the credentials. Check username, auth_id and password "
            f"in {local_config.config_path()}."
            + (f"\nWarning header: {res['warning']}" if res["warning"] else ""),
        )
    else:
        report.item(
            "FAIL", f"REGISTER → {status_label or 'no final response'}",
            (res["warning"] or res["error"] or "The registrar returned a non-2xx final response."),
        )


def _register_target(account, transport):
    """Resolve the host:port to register against, honouring outbound_proxy."""
    default_ports = {"udp": 5060, "tcp": 5090, "tls": 5096}
    proxy = (account.get("outbound_proxy") or "").strip()
    if not proxy:
        return account["domain"], default_ports[transport]
    if ":" in proxy:
        host, _, port = proxy.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return proxy, default_ports[transport]


def check_sip_alg(cfg, report, proxies=None):
    report.heading("SIP ALG Detection")
    settings = cfg["settings"]
    proxies = proxies if proxies is not None else cfg.get("sip_proxies", [])

    if not proxies:
        report.item("SKIP", "No SIP proxies configured")
        return

    report.note(
        "A SIP ALG on the firewall rewrites addresses inside unencrypted SIP as it "
        "passes. Because the proxy echoes our Via header back verbatim, a sent-by "
        "address or branch that comes back changed means something on the path "
        "rewrote it. This is the most common cause of one-way audio, failed "
        "registration and dropped calls on handsets using unencrypted SIP — and it "
        "cannot be detected on TLS, because an ALG cannot read encrypted signalling."
    )
    report.blank()

    for proxy in proxies:
        host = proxy["host"]
        for transport in ("tcp", "udp"):
            for port in proxy.get(transport, []):
                res = sip_probe.detect_sip_alg(
                    host, port, transport=transport, domain=host,
                    timeout=max(5.0, settings["timeout_seconds"]),
                )
                label = f"{host}:{port}/{transport.upper()}"

                if not res["ok"]:
                    report.item("SKIP", label, res["error"])
                    continue

                nat = []
                if res["received"]:
                    nat.append(f"public IP seen by the proxy: {res['received']}")
                if res["rport"] is not None:
                    nat.append(f"source port: {res['rport']}")
                nat_detail = ("Normal NAT traversal — " + ", ".join(nat) + ".") if nat else ""

                if res["alg_detected"]:
                    report.item(
                        "FAIL", f"{label} — SIP ALG detected",
                        "\n".join(res["evidence"])
                        + "\nDisable the SIP ALG / SIP transformations on the firewall. "
                        "RingCentral handles NAT itself via the rport mechanism and does "
                        "not need the firewall to rewrite anything.",
                    )
                else:
                    report.item(
                        "OK", f"{label} — signalling arrived unmodified",
                        f"Via returned intact as {res['returned_sent_by']} ({res['status']}). "
                        + nat_detail,
                    )
        report.blank()


def check_traceroute(cfg, report, proxies=None):
    report.heading("Traceroute")
    settings = cfg["settings"]
    proxies = proxies if proxies is not None else cfg.get("sip_proxies", [])
    if not proxies:
        report.item("SKIP", "No SIP proxies configured")
        return

    for proxy in proxies:
        host = proxy["host"]
        print(f"  Tracing route to {host} (this can take up to a minute)...")
        output = net_checks.traceroute(host, max_hops=settings.get("traceroute_max_hops", 20))
        if output is None:
            report.item("SKIP", f"Traceroute to {host}",
                        "Neither traceroute nor tracepath is available on this host.")
            continue
        report.item("INFO", f"Traceroute to {host}")
        for line in output.rstrip().split("\n"):
            report.line(f"           {line}")
        report.blank()


# ──────────────────────────────────────────────────────────────────────────────
# Menu actions
# ──────────────────────────────────────────────────────────────────────────────

def _full_check(cfg):
    proxies = _select_proxies(cfg, "Select (SPACE) SIP proxies to include in the full check:")
    if not proxies:
        return

    est = len(proxies) * (12 + cfg["settings"]["latency_samples"] * cfg["settings"]["sample_interval_ms"] / 1000 * 3)
    print(f"\nRunning full local health check against {len(proxies)} proxy/proxies "
          f"(roughly {est / 60:.1f} minutes). Press CTRL+C to abort.\n")

    report = Report("RingCentral-Tools — Local Network Health Check")
    check_local_info(cfg, report)
    check_dns(cfg, report)
    check_latency(cfg, report, proxies)
    check_tls(cfg, report, proxies)
    check_https(cfg, report)
    check_stun(cfg, report)
    check_sip_signalling(cfg, report, proxies)
    check_sip_alg(cfg, report, proxies)
    check_sip_register(cfg, report)
    if cfg["settings"].get("traceroute_enabled"):
        check_traceroute(cfg, report, proxies)
    report.summary()
    report.offer_export("LocalHealthCheck")


def _single(cfg, title, func, needs_proxies=False, export_name="LocalDiagnostics"):
    proxies = None
    if needs_proxies:
        proxies = _select_proxies(cfg)
        if not proxies:
            return
    report = Report(f"RingCentral-Tools — {title}")
    if needs_proxies:
        func(cfg, report, proxies)
    else:
        func(cfg, report)
    report.summary()
    report.offer_export(export_name)


def _show_config(cfg):
    path = local_config.config_path()
    account = cfg.get("sip_account", {})
    print("\n" + "─" * WIDTH)
    print(f"  Config file: {path.resolve()}")
    print(f"  Example:     {local_config.EXAMPLE_PATH.resolve()}")
    print("─" * WIDTH)
    print(f"  SIP proxies configured: {len(cfg.get('sip_proxies', []))}")
    for proxy in cfg.get("sip_proxies", []):
        ports = "  ".join(
            f"{t.upper()} {','.join(str(p) for p in proxy.get(t, []))}"
            for t in ("udp", "tcp", "tls") if proxy.get(t)
        )
        print(f"    - {proxy['host']:<28} {ports}")
    print(f"  HTTPS endpoints:  {len(cfg.get('https_endpoints', []))}")
    print(f"  STUN servers:     {len(cfg.get('stun_servers', []))}")
    print("─" * WIDTH)
    if local_config.sip_account_ready(cfg):
        print("  SIP account: ENABLED")
        print(f"    Username:  {account.get('username')}")
        print(f"    Auth ID:   {account.get('auth_id') or '(same as username)'}")
        print(f"    Password:  {'*' * 8} (set)")
        print(f"    Domain:    {account.get('domain')}")
        print(f"    Proxy:     {account.get('outbound_proxy') or '(use domain)'}")
        print(f"    Transport: {account.get('transport', 'tls').upper()}")
    else:
        print("  SIP account: NOT CONFIGURED")
        print("    Set sip_account.enabled to true and fill in username, password")
        print("    and domain to enable the SIP registration test.")
    print("─" * WIDTH)
    print("\n" + textwrap.fill(
        "Edit the config file in any text editor and choose a diagnostic again — the "
        "file is re-read every time this module starts. It is git-ignored because it "
        "can hold a SIP password.",
        width=WIDTH,
    ))


# ──────────────────────────────────────────────────────────────────────────────
# Module entry point
# ──────────────────────────────────────────────────────────────────────────────

def run(client=None):
    """Local network diagnostics. Runs entirely from this machine and never
    contacts the RingCentral API, so no tenancy connection is required.
    The client argument is accepted and ignored so this module can also be
    launched from the tenancy module menu."""
    try:
        cfg, created = local_config.load_config()
    except ValueError as e:
        print(f"\n{e}")
        print("Fix or delete the file and try again.")
        return

    print("\n" + "=" * WIDTH)
    print("  Local Diagnostics")
    print("=" * WIDTH)
    print(textwrap.fill(
        "Network health checks run from this machine against RingCentral's SIP and "
        "HTTPS endpoints. No RingCentral account is used. All checks are read-only "
        "and no calls are placed.",
        width=WIDTH,
    ))

    if created:
        print("\n" + textwrap.fill(
            f"A default configuration was created at {local_config.config_path()}. "
            "Review the SIP proxy list before relying on the results — the correct "
            "proxies differ by region and by tenancy.",
            width=WIDTH,
        ))

    menu_options = [
        "Run Full Local Health Check (everything below)",
        "Latency, Jitter & Packet Loss to SIP Proxies",
        "SIP Signalling Test (OPTIONS ping)",
        "SIP ALG Detection (firewall tampering on unencrypted SIP)",
        "SIP Registration Test (uses configured credentials)",
        "DNS Resolution Check",
        "NAT Behaviour Check (STUN)",
        "TLS Certificate Check",
        "HTTPS Endpoint Check",
        "Traceroute to SIP Proxies",
        "Local Host & Network Information",
        "Show Configuration",
        "Back to Launch Menu",
    ]

    while True:
        chosen, _ = pick(menu_options, "Select a local diagnostic:", indicator="►► ")

        try:
            if chosen.startswith("Run Full"):
                _full_check(cfg)
            elif chosen.startswith("Latency"):
                _single(cfg, "Latency, Jitter & Packet Loss", check_latency, True, "LatencyCheck")
            elif chosen.startswith("SIP Signalling"):
                _single(cfg, "SIP Signalling Test", check_sip_signalling, True, "SipSignallingTest")
            elif chosen.startswith("SIP ALG"):
                _single(cfg, "SIP ALG Detection", check_sip_alg, True, "SipAlgDetection")
            elif chosen.startswith("SIP Registration"):
                _single(cfg, "SIP Registration Test", check_sip_register, False, "SipRegistrationTest")
            elif chosen.startswith("DNS"):
                _single(cfg, "DNS Resolution Check", check_dns, False, "DnsCheck")
            elif chosen.startswith("NAT"):
                _single(cfg, "NAT Behaviour Check", check_stun, False, "NatCheck")
            elif chosen.startswith("TLS"):
                _single(cfg, "TLS Certificate Check", check_tls, True, "TlsCheck")
            elif chosen.startswith("HTTPS"):
                _single(cfg, "HTTPS Endpoint Check", check_https, False, "HttpsCheck")
            elif chosen.startswith("Traceroute"):
                _single(cfg, "Traceroute", check_traceroute, True, "Traceroute")
            elif chosen.startswith("Local Host"):
                _single(cfg, "Local Host & Network Information", check_local_info, False, "LocalHostInfo")
            elif chosen.startswith("Show Configuration"):
                # Re-read so edits made since the module started are picked up.
                cfg, _ = local_config.load_config()
                _show_config(cfg)
            else:
                return
        except KeyboardInterrupt:
            print("\n\nDiagnostic interrupted.")

        input("\nPress Enter to continue...")
