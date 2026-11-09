#!/usr/bin/env python3
"""
SABROXYY Nmap Scanner
=====================
A simple, interactive Nmap helper:

  1. You type the IP address or subnet to scan.
  2. You pick scan options from a menu (each option explains what its Nmap flag does).
  3. Nmap runs and you see its normal output.
  4. Every open port is labelled CRITICAL, MEDIUM or LOW risk, with the reason.

Only scan networks you own or have written permission to scan.

Usage:
    python3 sabroxyy.py                                  # interactive menu
    sudo python3 sabroxyy.py                             # needed for -sS, -sU, -O, -A
    python3 sabroxyy.py -t 192.168.1.0/24 -o 2,5,8 -y    # no questions asked
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Nmap's XML contains text sent by the scanned devices (banners, names), so prefer the
# hardened parser when it's installed (pip install defusedxml). Python's built-in parser
# does not fetch external entities, so it is an acceptable fallback.
try:
    from defusedxml.ElementTree import fromstring as parse_xml
except ImportError:  # pragma: no cover
    from xml.etree.ElementTree import fromstring as parse_xml

BANNER = r"""
███████╗ █████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██╗   ██╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝╚██╗ ██╔╝
███████╗███████║██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝  ╚████╔╝
╚════██║██╔══██║██╔══██╗██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝    ╚██╔╝
███████║██║  ██║██████╔╝██║  ██║╚██████╔╝██╔╝ ██╗   ██║      ██║
╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝
                    Nmap Network Scanner  ·  by SABROXYY
"""

# --------------------------------------------------------------------------- colours
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
COLORS = {
    "red": "31",
    "yellow": "33",
    "green": "32",
    "cyan": "36",
    "bold": "1",
    "dim": "2",
}


def paint(text: str, color: str, enabled: bool | None = None) -> str:
    on = USE_COLOR if enabled is None else enabled
    return f"\033[{COLORS[color]}m{text}\033[0m" if on else text


# --------------------------------------------------------------------------- scan options
@dataclass(frozen=True)
class Option:
    number: int
    flag: str
    name: str
    description: str
    group: str = ""  # options in the same group cannot be combined
    needs_root: bool = False


OPTIONS: list[Option] = [
    Option(
        1,
        "-sn",
        "Ping scan (host discovery)",
        "Finds which devices are online. Does NOT scan ports.",
        group="discovery",
    ),
    Option(
        2,
        "-sT",
        "TCP connect scan",
        "Completes the full TCP handshake on each port. Works without sudo.",
        group="tcp",
    ),
    Option(
        3,
        "-sS",
        "TCP SYN 'stealth' scan",
        "Sends SYN only (half-open). Faster and quieter than -sT.",
        group="tcp",
        needs_root=True,
    ),
    Option(
        4,
        "-sU",
        "UDP scan",
        "Finds UDP services such as DNS (53), SNMP (161), DHCP (67). Slow.",
        needs_root=True,
    ),
    Option(
        5,
        "-F",
        "Fast scan",
        "Scans only the 100 most common ports instead of 1000.",
        group="ports",
    ),
    Option(
        6,
        "-p-",
        "All ports",
        "Scans all 65,535 ports. Thorough but slow.",
        group="ports",
    ),
    Option(
        7,
        "-p",
        "Custom ports",
        "Scan only the ports you type, e.g. 22,80,443 or 1-1024.",
        group="ports",
    ),
    Option(
        8,
        "-sV",
        "Service / version detection",
        "Asks each open port what software and version is running.",
    ),
    Option(
        9,
        "-O",
        "OS detection",
        "Guesses the operating system (Linux, Windows, router...).",
        needs_root=True,
    ),
    Option(
        10,
        "-A",
        "Aggressive scan",
        "= -O + -sV + default scripts (-sC) + traceroute. Detailed but noisy.",
        needs_root=True,
    ),
    Option(
        11,
        "-Pn",
        "Skip host discovery",
        "Treats every host as online. Use when a firewall blocks ping.",
    ),
    Option(
        12,
        "-T4",
        "Faster timing",
        "Speeds the scan up (timing 0=slowest ... 5=fastest). Good on a LAN.",
    ),
    Option(
        13,
        "--open",
        "Show only open ports",
        "Hides closed and filtered ports in Nmap's output.",
    ),
]
OPTIONS_BY_NUMBER = {o.number: o for o in OPTIONS}
DEFAULT_CHOICE = "2 5 8"  # TCP connect + top 100 ports + versions: safe, no sudo
PORT_FLAGS = {"-F", "-p-", "-p"}
INCOMPATIBLE_WITH_PING = PORT_FLAGS | {"-sT", "-sS", "-sU", "-sV", "-O", "-A"}

# --------------------------------------------------------------------------- port risks
CRITICAL, MEDIUM, LOW = "CRITICAL", "MEDIUM", "LOW"

# port -> (risk level, why it matters)
PORT_RISKS: dict[int, tuple[str, str]] = {
    21: (CRITICAL, "FTP sends usernames and passwords in clear text"),
    22: (
        MEDIUM,
        "SSH remote login - common brute-force target; use keys, not passwords",
    ),
    23: (CRITICAL, "Telnet sends everything, including passwords, in clear text"),
    25: (MEDIUM, "SMTP mail server - check it is not an open relay"),
    53: (MEDIUM, "DNS - check it is not an open resolver (DDoS amplification)"),
    69: (CRITICAL, "TFTP has no authentication at all"),
    80: (MEDIUM, "HTTP website without encryption - prefer HTTPS"),
    110: (MEDIUM, "POP3 email in clear text - prefer POP3S (995)"),
    111: (CRITICAL, "RPCbind exposes internal services (NFS) - often abused"),
    135: (CRITICAL, "Windows RPC - frequently exploited, never expose to the internet"),
    137: (CRITICAL, "NetBIOS leaks computer and user names"),
    138: (CRITICAL, "NetBIOS leaks computer and user names"),
    139: (CRITICAL, "NetBIOS/SMB file sharing - frequently exploited"),
    143: (MEDIUM, "IMAP email in clear text - prefer IMAPS (993)"),
    161: (CRITICAL, "SNMP - default 'public' community leaks device configuration"),
    389: (MEDIUM, "LDAP directory - may leak users; prefer LDAPS (636)"),
    443: (LOW, "HTTPS encrypted website - keep the software updated"),
    445: (CRITICAL, "SMB file sharing - target of WannaCry/EternalBlue"),
    512: (CRITICAL, "rexec - legacy remote execution with weak authentication"),
    513: (CRITICAL, "rlogin - legacy remote login with weak authentication"),
    514: (CRITICAL, "rsh - legacy remote shell with weak authentication"),
    993: (LOW, "IMAPS encrypted email"),
    995: (LOW, "POP3S encrypted email"),
    1433: (CRITICAL, "Microsoft SQL Server database exposed"),
    1521: (CRITICAL, "Oracle database exposed"),
    2049: (CRITICAL, "NFS file shares - may allow mounting files remotely"),
    2375: (CRITICAL, "Docker API without TLS = full control of the host"),
    3306: (CRITICAL, "MySQL/MariaDB database exposed"),
    3389: (CRITICAL, "Remote Desktop (RDP) - top ransomware entry point"),
    5432: (CRITICAL, "PostgreSQL database exposed"),
    5900: (CRITICAL, "VNC remote desktop - often weak or no password"),
    5985: (CRITICAL, "WinRM remote management (HTTP)"),
    5986: (CRITICAL, "WinRM remote management"),
    6379: (CRITICAL, "Redis - no password by default, allows remote takeover"),
    8080: (MEDIUM, "Alternative HTTP / admin panel or proxy - check what it is"),
    8443: (LOW, "Alternative HTTPS / admin panel - check what it is"),
    9200: (CRITICAL, "Elasticsearch - often no authentication, data leaks"),
    11211: (CRITICAL, "Memcached - no authentication, DDoS amplification"),
    27017: (CRITICAL, "MongoDB - often no authentication, data leaks"),
}
UNKNOWN_RISK = (LOW, "Not in the known-risk list - make sure you expect this service")
RISK_COLOR = {CRITICAL: "red", MEDIUM: "yellow", LOW: "green"}


def classify_port(port: int) -> tuple[str, str]:
    """Return (risk level, reason) for an open port."""
    return PORT_RISKS.get(port, UNKNOWN_RISK)


# --------------------------------------------------------------------------- validation
_TARGET_RE = re.compile(r"^[A-Za-z0-9:][A-Za-z0-9.:/\-]*$")  # never starts with "-"
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
MIN_PREFIX_V4 = 16  # refuse anything bigger than a /16 (65,536 addresses)


def validate_targets(text: str) -> list[str]:
    """Split and check targets. Accepts IPs, subnets (CIDR), ranges and hostnames.

    Raises ValueError with a friendly message if something is wrong.
    """
    targets = text.replace(",", " ").split()
    if not targets:
        raise ValueError("please type at least one IP address or subnet")
    for t in targets:
        if not _TARGET_RE.match(t):
            raise ValueError(f"'{t}' is not a valid IP, subnet or hostname")
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                raise ValueError(f"'{t}' is not a valid subnet (example: 192.168.1.0/24)") from None
            if net.version == 4 and net.prefixlen < MIN_PREFIX_V4:
                raise ValueError(
                    f"'{t}' is {net.num_addresses:,} addresses - too big. "
                    f"Use /{MIN_PREFIX_V4} or smaller (e.g. /24 = 256 addresses)"
                )
    return targets


def validate_ports(text: str) -> str:
    ports = text.replace(" ", "")
    if not _PORTS_RE.match(ports):
        raise ValueError("ports must look like 22,80,443 or 1-1024")
    for part in re.split(r"[,-]", ports):
        if not 1 <= int(part) <= 65535:
            raise ValueError(f"port {part} is out of range (1-65535)")
    return ports


def parse_choices(text: str) -> list[Option]:
    """Turn '2 5 8' or '2,5,8' into options and check they can be combined."""
    text = text.strip() or DEFAULT_CHOICE
    chosen: list[Option] = []
    for token in text.replace(",", " ").split():
        if not token.isdigit() or int(token) not in OPTIONS_BY_NUMBER:
            raise ValueError(f"'{token}' is not an option number (1-{len(OPTIONS)})")
        opt = OPTIONS_BY_NUMBER[int(token)]
        if opt not in chosen:
            chosen.append(opt)

    flags = {o.flag for o in chosen}
    for group in ("tcp", "ports"):
        same = [o for o in chosen if o.group == group]
        if len(same) > 1:
            names = " and ".join(f"{o.number} ({o.flag})" for o in same)
            raise ValueError(f"choose only one of {names}")
    if "-sn" in flags and flags & INCOMPATIBLE_WITH_PING:
        raise ValueError(
            "option 1 (-sn) only finds live hosts; it can't be combined with port scans"
        )
    return chosen


def is_root() -> bool:
    # Windows has no geteuid; Nmap there uses Npcap and handles privileges itself.
    return not hasattr(os, "geteuid") or os.geteuid() == 0


def build_command(options: list[Option], targets: list[str], ports: str | None = None) -> list[str]:
    cmd = ["nmap"]
    for opt in options:
        if opt.flag == "-p":
            if not ports:
                raise ValueError("custom ports (option 7) need a port list")
            cmd += ["-p", ports]
        else:
            cmd.append(opt.flag)
    return cmd + targets


# --------------------------------------------------------------------------- results
@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    risk: str
    reason: str


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    os_guess: str = ""
    ports: list[OpenPort] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    """Read Nmap's XML output (-oX) and keep the hosts that are up with their open ports."""
    root = parse_xml(xml_text)
    hosts: list[HostResult] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = next(
            (a.get("addr", "") for a in h.findall("address") if a.get("addrtype") != "mac"),
            "",
        )
        name = h.find("hostnames/hostname")
        osmatch = h.find("os/osmatch")
        host = HostResult(
            address=addr,
            hostname=name.get("name", "") if name is not None else "",
            os_guess=osmatch.get("name", "") if osmatch is not None else "",
        )
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if not state.startswith("open"):  # open, open|filtered
                continue
            svc = p.find("service")
            service = svc.get("name", "") if svc is not None else ""
            version = (
                " ".join(
                    v
                    for v in (
                        svc.get("product"),
                        svc.get("version"),
                        svc.get("extrainfo"),
                    )
                    if v
                )
                if svc is not None
                else ""
            )
            port = int(p.get("portid", "0"))
            risk, reason = classify_port(port)
            host.ports.append(
                OpenPort(
                    port,
                    p.get("protocol", "tcp"),
                    state,
                    service,
                    version,
                    risk,
                    reason,
                )
            )
        hosts.append(host)
    return hosts


def render_report(hosts: list[HostResult], command: list[str], color: bool) -> str:
    """Build the human-readable result table."""

    def c(text: str, col: str) -> str:
        return paint(text, col, color)

    lines = [
        c("=" * 78, "cyan"),
        c(" SABROXYY SCAN REPORT", "bold") + f"   {datetime.now():%Y-%m-%d %H:%M:%S}",
        f" Command: {' '.join(command)}",
        c("=" * 78, "cyan"),
    ]
    if not hosts:
        lines.append(" No hosts are up (or they block discovery - try option 11, -Pn).")
        return "\n".join(lines)

    totals = {CRITICAL: 0, MEDIUM: 0, LOW: 0}
    for host in hosts:
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        lines.append("")
        lines.append(c(f" Host: {title}", "bold"))
        if host.os_guess:
            lines.append(f" OS guess: {host.os_guess}")
        if not host.ports:
            lines.append(c("   Online - no open ports found in the scanned range.", "dim"))
            continue
        lines.append(f"   {'PORT':<10}{'SERVICE':<14}{'VERSION':<28}RISK")
        lines.append("   " + "-" * 74)
        for p in host.ports:
            totals[p.risk] += 1
            version = (p.version[:24] + "...") if len(p.version) > 27 else p.version
            lines.append(
                f"   {f'{p.port}/{p.protocol}':<10}{p.service[:13]:<14}{version:<28}"
                + c(f"{p.risk:<9}", RISK_COLOR[p.risk])
            )
            lines.append(c(f"   {'':<10}-> {p.reason}", "dim"))

    lines += [
        "",
        c("-" * 78, "cyan"),
        " Summary: "
        + c(f"{totals[CRITICAL]} CRITICAL", "red")
        + "  |  "
        + c(f"{totals[MEDIUM]} MEDIUM", "yellow")
        + "  |  "
        + c(f"{totals[LOW]} LOW", "green"),
    ]
    if totals[CRITICAL]:
        lines.append(c(" ! Close or firewall CRITICAL ports unless you really need them,", "red"))
        lines.append(c("   and never expose them to the internet.", "red"))
    lines.append(c("-" * 78, "cyan"))
    return "\n".join(lines)


# --------------------------------------------------------------------------- interaction
def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise KeyboardInterrupt from None


def show_menu() -> None:
    print(paint("\n Scan options", "bold") + paint("  (Nmap flag -> what it does)", "dim"))
    print(" " + "-" * 76)
    for o in OPTIONS:
        sudo = paint(" [sudo]", "yellow") if o.needs_root else ""
        print(f" {o.number:>2}) {paint(f'{o.flag:<7}', 'cyan')} {o.name}{sudo}")
        print(paint(f"              {o.description}", "dim"))
    print(" " + "-" * 76)
    print(
        paint(
            f" Combine numbers with spaces. Press Enter for the default: {DEFAULT_CHOICE}",
            "dim",
        )
    )
    print(paint("   (TCP connect scan + 100 common ports + version detection)", "dim"))


def ask_targets() -> list[str]:
    print(paint("\n Target examples:", "bold"))
    print("   single IP   192.168.1.10")
    print("   subnet      192.168.1.0/24   (256 addresses)")
    print("   range       192.168.1.1-50")
    print("   several     192.168.1.1 192.168.1.20")
    while True:
        try:
            return validate_targets(ask(paint("\n Enter IP or subnet to scan: ", "cyan")))
        except ValueError as exc:
            print(paint(f" x {exc}", "red"))


def ask_options() -> tuple[list[Option], str | None]:
    show_menu()
    while True:
        try:
            options = parse_choices(ask(paint("\n Choose options: ", "cyan")))
            break
        except ValueError as exc:
            print(paint(f" x {exc}", "red"))
    ports = None
    if any(o.flag == "-p" for o in options):
        while True:
            try:
                ports = validate_ports(
                    ask(paint(" Ports to scan (e.g. 22,80,443 or 1-1024): ", "cyan"))
                )
                break
            except ValueError as exc:
                print(paint(f" x {exc}", "red"))
    return options, ports


def confirm(prompt: str) -> bool:
    return ask(paint(prompt, "cyan")).strip().lower() in ("y", "yes")


def run_nmap(command: list[str]) -> str:
    """Run Nmap, showing its normal output, and return its XML output."""
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "scan.xml"
        # The list form (no shell) means nothing typed by the user can run extra commands.
        result = subprocess.run([*command, "-oX", str(xml_path)], check=False)
        if result.returncode != 0 or not xml_path.exists():
            raise RuntimeError(
                f"Nmap failed (exit code {result.returncode}) - see the message above"
            )
        return xml_path.read_text(encoding="utf-8", errors="replace")


def save_report(report: str) -> Path:
    folder = Path("reports")
    folder.mkdir(exist_ok=True)
    path = folder / f"scan_{datetime.now():%Y%m%d_%H%M%S}.txt"
    path.write_text(report + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SABROXYY interactive Nmap scanner")
    parser.add_argument("-t", "--target", help="IP, subnet or hostname (skips the question)")
    parser.add_argument("-o", "--options", help="option numbers, e.g. 2,5,8 (skips the menu)")
    parser.add_argument("-p", "--ports", help="ports for option 7, e.g. 22,80,443")
    parser.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    parser.add_argument("-s", "--save", action="store_true", help="save the report to reports/")
    args = parser.parse_args(argv)

    print(paint(BANNER, "cyan"))
    print(paint(" Only scan networks you own or have permission to scan.", "yellow"))

    if shutil.which("nmap") is None:
        print(paint(" x Nmap is not installed. Install it first:", "red"))
        print("     Ubuntu/Debian: sudo apt install nmap")
        print("     macOS:         brew install nmap")
        print("     Windows:       https://nmap.org/download.html")
        return 1

    try:
        targets = validate_targets(args.target) if args.target else ask_targets()
        if args.options:
            options = parse_choices(args.options)
            ports = validate_ports(args.ports) if args.ports else None
            if any(o.flag == "-p" for o in options) and not ports:
                raise ValueError("option 7 needs --ports, e.g. --ports 22,80,443")
        else:
            options, ports = ask_options()

        needs_root = [o for o in options if o.needs_root]
        if needs_root and not is_root():
            flags = ", ".join(o.flag for o in needs_root)
            print(paint(f"\n x {flags} needs administrator rights. Run again with:", "red"))
            print("     sudo python3 sabroxyy.py")
            print(paint("   or choose option 2 (-sT) instead of 3 (-sS).", "dim"))
            return 1

        command = build_command(options, targets, ports)
        print("\n You chose:")
        for o in options:
            print(f"   {paint(f'{o.flag:<7}', 'cyan')} {o.name}")
        print(f"\n Command: {paint(' '.join(command), 'bold')}")
        if not args.yes and not confirm(" Start the scan? [y/N] "):
            print(" Cancelled.")
            return 0

        print()
        hosts = parse_nmap_xml(run_nmap(command))
        print()
        print(render_report(hosts, command, USE_COLOR))

        if args.save or (not args.yes and confirm("\n Save this report to a file? [y/N] ")):
            print(f" Saved: {save_report(render_report(hosts, command, color=False))}")
        return 0
    except ValueError as exc:
        print(paint(f" x {exc}", "red"))
        return 2
    except RuntimeError as exc:
        print(paint(f" x {exc}", "red"))
        return 1
    except KeyboardInterrupt:
        print("\n Bye!")
        return 130


if __name__ == "__main__":
    sys.exit(main())
