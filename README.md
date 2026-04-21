# ICEbreaker

> *"The ice isn't going to break itself."*

ICEbreaker is a cyberpunk-themed network service discovery and vulnerability detection toolkit built for penetration testers, red teamers, and security researchers. It is designed to work alongside **nmap** — consuming its output formats and extracting actionable intelligence from scan results.

---

## Tools

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

## Design Philosophy

ICEbreaker tools are designed to:

- **Consume nmap output** — not replace nmap. Run your scans, feed the results in.
- **Be pipe-friendly** — output modes designed to chain into other tools.
- **Stay minimal** — stdlib-first, no heavy dependencies.
- **Report to stderr, output to stdout** — informational messages never pollute piped output.

---

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)
- nmap output files (`.gnmap` or `.xml`) as input

---

## Suggested Workflow

```
nmap -sS -p- -oA scan target_range
         |
         v
   port_frequer.py        <- what ports are most common?
         |
         v
   certsiphon.py          <- what domains/orgs are on those services?
         |
         v
   follow-on tooling      <- subdomain enum, vuln scanning, etc.
```

---

## Disclaimer

ICEbreaker is intended for use on networks and systems you own or have explicit written authorization to test. Unauthorized use against systems you do not have permission to test is illegal. The authors assume no liability for misuse.
