# ICEbreaker

> *"You've seen a lot of cowboy kinos, right? Well, the stuff they make up for those things isn't much, compared with the kind of shit a real heavy operator can front. Particularly when it comes to icebreakers. Heavy icebreakers are kind of funny to deal in, even for the big boys You know why? Because ice, all the really hard stuff, the walls around every major store of data in the matrix, is always the produce of an AI, an ariificial intelligence. Nothing else is fast enough to weave good ice and constantly alter and upgrade it. So when a really powerful icebreaker shows up on the black market, there are already a couple of very dicey factors in play."* Beauvoir from Count Zero

ICEbreaker is a cyberpunk-themed network service discovery and vulnerability detection toolkit built for penetration testers, red teamers, and security researchers. It is designed to work alongside **nmap** — consuming its output formats and extracting actionable intelligence from scan results.

---

## Tools

### netsight.py
Multi-phase network visibility and host discovery automation. Drives nmap through a progressive discovery pipeline — ping sweep, FQDN resolution, dark IP detection, full enumeration, firewall evasion, and source port scanning. Detects anomalous network conditions (honey-pots, tarpits, all-responding networks) and automatically falls back to a safe conservative scan.

**Features:**
- Six-phase scan pipeline: ping sweep → dark IP discovery → top port enumeration → full 65k scan → evasion scans → source port scans
- Flat configuration file (`netsight.conf`) with all settings overridable via CLI flags
- Anomalous network detection — warns loudly and falls back if >N% of hosts respond to ping or >N% of ports appear open
- Configurable thresholds for anomaly detection (`PING_RESPONSE_THRESHOLD`, `OPEN_PORT_THRESHOLD`)
- Fallback scan mode for known hostile or honey-pot networks
- Dry-run mode — prints every nmap command without executing
- Per-phase toggles: skip full TCP, skip UDP, skip evasion, skip source ports
- Generates interim output files after phase 3 so follow-on testing can begin while 65k scans run
- Source port scans across known trusted ports to detect firewall misconfigurations
- Requires nmap and sudo

**Quick start:**
```bash
# Standard run with default config
python3 netsight.py

# Dry run — see all commands before executing
python3 netsight.py --dry-run

# Custom targets, skip slow phases
python3 netsight.py --targets scope.txt --no-full-tcp --no-source-ports

# Run fallback scan only (suspected honey-pot network)
python3 netsight.py --fallback-only

# Tighten anomaly detection
python3 netsight.py --ping-threshold 60 --port-threshold 70

# Output to specific directory
python3 netsight.py --output-dir ./client-results
```

---

### port_frequer.py
Analyzes grepable nmap output (`.gnmap`) and reports open port frequency across all scanned hosts. Useful for quickly identifying the most common services in a large network scan and building targeted port lists for follow-on tooling.

**Features:**
- Ingests single files, comma-separated lists, or glob patterns (`"tcp*.gnmap"`)
- Outputs port frequency sorted by occurrence count (highest first)
- Single-line comma-separated port list mode (`-l`) for piping directly into other tools
- File export (`-o`)

**Quick start:**
```bash
# Frequency report
python3 port_frequer.py scan.gnmap

# Single-line port list (pipe into nmap, masscan, etc.)
python3 port_frequer.py -l scan.gnmap

# Multiple files via glob
python3 port_frequer.py "tcp*.gnmap" -o results.txt
```

---

### certsiphon.py
Siphons FQDNs and second-level domains from TLS certificates discovered across nmap scan results. Connects to each open TCP port, performs TLS handshakes (including STARTTLS for SMTP, IMAP, POP3, FTP), and extracts Subject Alternative Names (SANs), Common Names (CN), and Organization fields.

**Features:**
- Ingests `.gnmap` and nmap XML (`.xml`) formats
- Single file, comma-separated list, or glob pattern input
- Threaded scanning with configurable concurrency and rate limiting
- Auto-detected STARTTLS for standard ports; forceable on non-standard ports
- Extracts CN, SAN DNS, SAN IP, and Organization fields
- FQDN validation and second-level domain (SLD) extraction
- Certificate flagging: expired, near-expiry, self-signed, wildcard
- Optional port filtering to known TLS/STARTTLS ports only
- Output modes: default summary, single-line FQDN list, SLD-only, JSON, CSV
- File export

**Quick start:**
```bash
# Default output: per-host cert details + FQDN/SLD summary
python3 certsiphon.py scan.gnmap

# Single-line FQDN list for piping into other tools
python3 certsiphon.py -l scan.gnmap

# Only probe known TLS ports, 20 threads, export JSON
python3 certsiphon.py --tls-ports-only -t 20 --json -o certs.json scan.gnmap

# Find expired or self-signed certs
python3 certsiphon.py --flags expired self-signed scan.gnmap

# STARTTLS on a non-standard SMTP port
python3 certsiphon.py --starttls smtp --extra-ports 2525 scan.gnmap
```

---

### httpsiphon.py
Detects HTTP and HTTPS services across hosts and ports discovered in nmap scan output. Uses raw TCP sockets with no external dependencies — attempts plain HTTP first, falls back to HTTPS. Extracts status codes, server headers, redirect targets, auth requirements, and optionally page titles.

**Features:**
- Ingests `.gnmap` and nmap XML (`.xml`) formats
- Single file, comma-separated list, or glob pattern input
- Raw socket detection — no external tools required
- Auto-detects HTTP vs HTTPS per port
- Extracts status code, Server header, Location, WWW-Authenticate, X-Powered-By
- Optional page title extraction (`--grab-title`)
- Security header gap detection (`--missing-headers`)
- Filter by protocol, status code, or security header flags
- Output modes: default (one URL per line), comma list, JSON, CSV
- File export

**Quick start:**
```bash
# Default output: one URL per line
python3 httpsiphon.py scan.gnmap

# Grab page titles
python3 httpsiphon.py scan.gnmap --grab-title

# HTTPS services only
python3 httpsiphon.py scan.gnmap --https-only

# Find services missing security headers
python3 httpsiphon.py scan.gnmap --missing-headers

# Filter to login pages and forbidden responses
python3 httpsiphon.py scan.gnmap --status 401 403

# Comma-separated URL list for piping into other tools
python3 httpsiphon.py scan.gnmap -l
```

---

### tlscertinspector.py
Single-target TLS certificate inspection utility. Connects to a given `host:port`, performs a TLS handshake, and prints a detailed breakdown of the certificate — useful for quickly inspecting a specific service without running a full scan.

**Features:**
- Single `host:port` target input
- Full certificate details: subject, issuer, serial number, validity window, expiry countdown
- Subject Alternative Names (SANs) — DNS and IP
- OCSP and CA Issuer URLs from the Authority Information Access extension
- TLS protocol version and cipher suite reported
- Flags expired certificates clearly
- Requires `cryptography` library: `pip install cryptography`

**Quick start:**
```bash
# Inspect a certificate
python3 tlscertinspector.py example.com:443

# Non-standard port
python3 tlscertinspector.py 10.1.2.3:8443

# IPv6
python3 tlscertinspector.py [::1]:443
```

**Example output:**
```
============================================================
  TLS Certificate — example.com:443
============================================================
  Protocol           TLSv1.3
  Cipher             TLS_AES_256_GCM_SHA384 (256-bit)
------------------------------------------------------------
  Subject            CN=example.com, O=Example Org, C=US
  Issuer             CN=R11, O=Let's Encrypt, C=US
  Serial             0x deadbeef...
------------------------------------------------------------
  Not Before         2025-01-01 00:00:00 UTC
  Not After          2025-04-01 00:00:00 UTC (in 90 days)
------------------------------------------------------------
  Subject Alt Names:
    • DNSName:example.com
    • DNSName:www.example.com
============================================================
```

---

## Design Philosophy

ICEbreaker tools are designed to:

- **Consume nmap output** — not replace nmap. Run your scans, feed the results in.
- **Be pipe-friendly** — output modes designed to chain into other tools.
- **Stay minimal** — stdlib-first, no heavy dependencies.
- **Report to stderr, output to stdout** — informational messages never pollute piped output.
- **Fail loudly** — anomalous conditions produce unmissable warnings, not silent failures.

---

## Requirements

- Python 3.8+
- `pip install cryptography` — required by `certsiphon.py` and `tlscertinspector.py`
- nmap installed and available in PATH (`netsight.py` also requires sudo)
- nmap output files (`.gnmap` or `.xml`) as input for post-processing tools

---

## Suggested Workflow

```
          [ targets.txt ]
                |
                v
          netsight.py             <- discover live hosts, enumerate ports
                |
        +-------+-------+
        |               |
        v               v
  port_frequer.py   certsiphon.py  <- what ports are common? what domains?
        |               |
        v               v
  httpsiphon.py    follow-on       <- which ports run HTTP/HTTPS?
        |
        v
  follow-on tooling                <- app scanning, vuln detection, etc.
```

---

## Disclaimer

ICEbreaker is intended for use on networks and systems you own or have explicit written authorization to test. Unauthorized use against systems you do not have permission to test is illegal. The authors assume no liability for misuse.
