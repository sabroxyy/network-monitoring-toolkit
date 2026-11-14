<div align="center">

# 🛰️ Network Monitoring Toolkit

**An interactive Nmap scanner in Python that tells you which open ports are dangerous, and why.**

[![CI](https://github.com/sabroxyy/network-monitoring-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/sabroxyy/network-monitoring-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/powered%20by-Nmap-4682B4)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

<!-- DEMO: record a 10–15s terminal clip (e.g. with `vhs` or `asciinema` + `agg`),
     save it as docs/demo.gif, then delete this comment and uncomment the line below. -->
<!-- <img src="docs/demo.gif" alt="netscan demo" width="760"> -->

</div>

---

## ✨ Why this tool

Nmap tells you a port is **open**. It doesn't tell you whether you should **worry**.
`netscan.py` wraps Nmap in a guided menu and turns the results into a risk report:

- 🧭 **Guided menu**: every option shows its Nmap flag (`-sS`, `-sV`, …) and explains it in plain English
- 🚦 **Risk rating**: each open port is labelled 🔴 **CRITICAL**, 🟡 **MEDIUM** or 🟢 **LOW**, with the reason
- 🛡️ **Safe by default**: validates targets, refuses subnets larger than `/16`, blocks conflicting flags
- ⚡ **Quick mode**: one-line, non-interactive scans for scripts and cron jobs
- 📄 **Saved reports**: timestamped text reports in `reports/`
- 📦 **Zero dependencies**: one file, Python standard library only, tested in CI on 3.9 / 3.12 / 3.13

> ⚠️ **Only scan networks you own or have written permission to scan.** Scanning other people's networks may be illegal.

---

## 🚀 Quick start

```bash
# 1. Install Nmap
sudo apt install nmap            # Ubuntu / Debian / Kali
# brew install nmap              # macOS
# Windows: https://nmap.org/download.html

# 2. Get the tool
git clone https://github.com/sabroxyy/network-monitoring-toolkit.git
cd network-monitoring-toolkit

# 3. Run it
python3 netscan.py               # interactive menu
sudo python3 netscan.py          # needed for -sS, -sU, -O, -A
```

Optional: `pip install defusedxml` adds a hardened XML parser.

---

## 🖥️ What it looks like

**Pick a target and options:**

```
 Enter IP or subnet to scan: 192.168.1.0/24

 Scan options  (Nmap flag -> what it does)
 ----------------------------------------------------------------------------
  1) -sn     Ping scan (host discovery)
              Finds which devices are online. Does NOT scan ports.
  2) -sT     TCP connect scan
              Completes the full TCP handshake on each port. Works without sudo.
  3) -sS     TCP SYN 'stealth' scan [sudo]
  ...
 Choose options: 2 5 8

 Command: nmap -sT -F -sV 192.168.1.0/24
 Start the scan? [y/N] y
```

**Get a risk report:**

```
==============================================================================
 SABROXYY SCAN REPORT   2026-11-09 14:28:26
 Command: nmap -sT -F -sV 192.168.1.0/24
==============================================================================

 Host: 192.168.1.20 (nas.lan)
   PORT      SERVICE       VERSION                     RISK
   --------------------------------------------------------------------------
   22/tcp    ssh           OpenSSH 9.6                 MEDIUM
             -> SSH remote login - common brute-force target; use keys, not passwords
   445/tcp   microsoft-ds  Samba smbd 4.6.2            CRITICAL
             -> SMB file sharing - target of WannaCry/EternalBlue
   443/tcp   https         nginx 1.24.0                LOW
             -> HTTPS encrypted website - keep the software updated

------------------------------------------------------------------------------
 Summary: 1 CRITICAL  |  1 MEDIUM  |  1 LOW
 ! Close or firewall CRITICAL ports unless you really need them,
   and never expose them to the internet.
------------------------------------------------------------------------------
```

---

## ⚡ Quick mode (no questions)

```bash
python3 netscan.py -t 192.168.1.10 -o 2,5,8 -y        # target + options, no confirm
python3 netscan.py -t 192.168.1.10 -o 2,7 -p 22,80 -y  # custom ports
python3 netscan.py -t 192.168.1.0/24 -o 1 -y -s       # find live hosts, save report
```

| Argument | Meaning |
|---|---|
| `-t` / `--target` | IP, subnet, range or hostname |
| `-o` / `--options` | Menu numbers, e.g. `2,5,8`, or flags written with `=`: `-o=-sT,-sV` |
| `-p` / `--ports` | Ports for option 7, e.g. `22,80,443` |
| `-y` / `--yes` | Don't ask for confirmation |
| `-s` / `--save` | Save the report to `reports/` |

---

## 📚 Reference

<details>
<summary><b>Targets you can type</b></summary>

| Type | Example | Meaning |
|---|---|---|
| Single IP | `192.168.1.10` | One device |
| Subnet (CIDR) | `192.168.1.0/24` | 256 addresses (192.168.1.0 – 192.168.1.255) |
| Range | `192.168.1.1-50` | Addresses .1 to .50 |
| Several | `192.168.1.1 192.168.1.20` | Separate with spaces or commas |
| Hostname | `router.lan` | A name your network can resolve |

For safety, subnets bigger than `/16` (65,536 addresses) are refused.

</details>

<details>
<summary><b>Menu options: what each Nmap flag does</b></summary>

| # | Flag | Name | What it does | Needs sudo |
|---|---|---|---|---|
| 1 | `-sn` | Ping scan | Finds which devices are online. **No port scan.** | |
| 2 | `-sT` | TCP connect scan | Completes the full TCP handshake (SYN → SYN/ACK → ACK) on each port. Reliable and works without admin rights, but easy to log. | |
| 3 | `-sS` | TCP SYN "stealth" scan | Sends only SYN and never completes the handshake (half-open). Faster and quieter. The default when run as root. | ✅ |
| 4 | `-sU` | UDP scan | Finds UDP services like DNS (53), SNMP (161), DHCP (67). Slow because UDP rarely replies. | ✅ |
| 5 | `-F` | Fast scan | Scans the 100 most common ports instead of the default 1,000. | |
| 6 | `-p-` | All ports | Scans all 65,535 ports. Thorough but slow. | |
| 7 | `-p` | Custom ports | Only the ports you list: `-p 22,80,443` or `-p 1-1024`. | |
| 8 | `-sV` | Version detection | Talks to each open port to find the software and version (e.g. `OpenSSH 9.6`). | |
| 9 | `-O` | OS detection | Guesses the operating system from how the device answers. | ✅ |
| 10 | `-A` | Aggressive | Shortcut for `-O` + `-sV` + default scripts (`-sC`) + traceroute. Very detailed and very noisy. | ✅ |
| 11 | `-Pn` | Skip host discovery | Treats every host as online. Use it when a firewall blocks ping and hosts look "down". | |
| 12 | `-T4` | Faster timing | Timing templates go from `-T0` (paranoid, slowest) to `-T5` (insane). `-T4` is good on a fast LAN. | |
| 13 | `--open` | Only open ports | Hides closed/filtered ports in Nmap's output. | |

**How to choose:** type menu numbers or the flags themselves, separated by spaces,
commas, `&` or `and`. These all mean the same thing:
`2 5 8` · `2,5,8` · `2 & 5 & 8` · `-sT -F -sV`

**Rules the script checks for you:**
- Choose only one of `-sT` and `-sS`.
- Choose only one of `-F`, `-p-` and `-p`.
- `-sn` can't be combined with port scans. It only lists which devices are online. To
  find devices *and* see their ports, first run `1` on the subnet, then run `2 5 8` (or
  `3 5 8` with sudo) on the devices you found.
- IPv4 addresses need 4 parts: `192.168.1.11-20` is valid, `192.168.11-20` is not.

**Good combinations:**

| Goal | Options | Command |
|---|---|---|
| Who is on my network? | `1` | `nmap -sn 192.168.1.0/24` |
| Quick check, no sudo (default) | `2 5 8` | `nmap -sT -F -sV 192.168.1.10` |
| Fast stealth scan | `3 5 12` (sudo) | `nmap -sS -F -T4 192.168.1.10` |
| Everything about one device | `10 6` (sudo) | `nmap -A -p- 192.168.1.10` |
| Device blocks ping | `2 11 8` | `nmap -sT -Pn -sV 192.168.1.10` |

</details>

<details>
<summary><b>More Nmap flags: cheat sheet</b></summary>

These aren't in the menu, but they're useful to know when you run `nmap` yourself.

| Flag | What it does |
|---|---|
| `-sA` | ACK scan: maps firewall rules (filtered vs unfiltered), not open ports |
| `-sF` `-sN` `-sX` | FIN / NULL / Xmas scans: odd packets that can slip past simple firewalls |
| `-sC` | Run the default NSE scripts (safe information gathering) |
| `--script <name>` | Run specific NSE scripts, e.g. `--script vuln` (can be intrusive!) |
| `--top-ports <n>` | Scan the *n* most common ports |
| `-p U:53,T:80` | Mix UDP and TCP ports |
| `-6` | Scan IPv6 addresses |
| `-n` / `-R` | Never / always do reverse-DNS lookups |
| `-v` / `-vv` | More detail while scanning |
| `--reason` | Show *why* a port is open/closed/filtered |
| `-iL <file>` | Read targets from a file |
| `--exclude <ip>` | Skip these addresses |
| `-oN` / `-oX` / `-oG` / `-oA` | Save output as normal text / XML / grepable / all formats |
| `-S <ip>` | Spoof the **source** IP address (replies won't come back to you; rarely useful) |
| `-D <decoys>` | Hide your scan among decoy IPs |
| `-f` | Fragment packets (evade simple packet filters) |
| `--max-rate <n>` | Send at most *n* packets per second (be gentle with fragile devices) |

Note that capital `-S` (spoof source address) is completely different from the
lowercase `-s` scan types (`-sS`, `-sT`, `-sU`, …).

</details>

<details open>
<summary><b>Port risk levels</b></summary>

| Level | Meaning | Examples |
|---|---|---|
| 🔴 **CRITICAL** | Often attacked, sends passwords in clear text, or gives direct control/data access. Close it or firewall it. | 21 FTP, 23 Telnet, 135/139/445 Windows/SMB, 161 SNMP, 1433 MSSQL, 2375 Docker, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 5900 VNC, 6379 Redis, 9200 Elasticsearch, 27017 MongoDB |
| 🟡 **MEDIUM** | Normal services that need correct configuration. | 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 389 LDAP, 8080 HTTP-alt |
| 🟢 **LOW** | Encrypted or not in the known-risk list. Still check that you expect it. | 443 HTTPS, 993 IMAPS, 995 POP3S, other ports |

The full list with reasons is the `PORT_RISKS` table at the top of
[`netscan.py`](netscan.py). Edit it to fit your network.

</details>

---

## 🗂️ Project files

```
network-monitoring-toolkit/
├── netscan.py               # the scanner (one file, no dependencies)
├── tests/test_netscan.py    # automated tests:  python3 -m pytest -q
├── reports/                 # saved reports (created when you save one; git-ignored)
├── .github/workflows/ci.yml # runs the tests on every push
├── README.md
└── LICENSE
```

---

## 🛣️ Roadmap

- [ ] Export reports as HTML / CSV
- [ ] Compare two scans and show new or closed ports (`ndiff`-style)
- [ ] Scheduled scans with alerts

Ideas and pull requests are welcome. Open an [issue](https://github.com/sabroxyy/network-monitoring-toolkit/issues) first for bigger changes.

---

## ⚖️ Legal

Use this tool only on systems you own or are **explicitly authorised** to test.
The author is not responsible for misuse.

<div align="center">

Built by **[Sabry Ayoub](https://github.com/sabroxyy)**, network & security engineer · [LinkedIn](https://www.linkedin.com/in/sabryayoub) · MIT License

⭐ **If this helped you, star the repo so others can find it.**

</div>
