#!/usr/bin/env python3
"""certsiphon — Siphon FQDNs and SLDs from TLS certificates in nmap scan output."""

import argparse
import csv
import io
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from xml.etree import ElementTree
import glob as glob_module

BANNER = r"""
  +------------------------------------------------------------------+
  | 4f:9c SAN:*.io x509 CN:foo.com 3a7 rsa2048 0xff TLS pem SHA256  |
  | db:f2 OCSP CRL cert chain subjectAltName commonName 4a:9c:bb:12 |
  | 9b:3f issuer *.corp.lan 7f:aa commonName expired wildcard 0x4e   |
  | SAN DNS:api.io 2048 x509v3 fingerprint SHA1 notAfter CN:*.io     |
  +-----------------------------------+------------------------------+
                                      |  )))
                                      |  )))
                                      |  )))
                                      v
  +-----------------------------------+------------------------------+
  |                                                                  |
  |                    c e r t s i p h o n                          |
  +------------------------------------------------------------------+
"""

# Ports that commonly run direct TLS
TLS_PORTS = {
    443, 465, 636, 993, 995, 1443, 2083, 2087, 2096,
    3443, 4443, 5061, 6443, 7443, 8443, 8883, 9443, 10443
}

# Ports that use STARTTLS and their associated protocol
STARTTLS_PORTS = {
    21:  'ftp',
    25:  'smtp',
    110: 'pop3',
    143: 'imap',
    587: 'smtp',
}

NEAR_EXPIRY_DAYS = 30

FQDN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


# ---------------------------------------------------------------------------
# File parsing
# ---------------------------------------------------------------------------

def parse_gnmap(filepath):
    """Return list of (host, port) from a grepable nmap (.gnmap) file."""
    targets = []
    port_re = re.compile(r'(\d+)/open/tcp')
    with open(filepath) as f:
        for line in f:
            if not line.startswith('Host:'):
                continue
            host = line.split()[1]
            for port in port_re.findall(line):
                targets.append((host, int(port)))
    return targets


def parse_nmap_xml(filepath):
    """Return list of (host, port) from an nmap XML (.xml) file."""
    targets = []
    tree = ElementTree.parse(filepath)
    for host in tree.findall('.//host'):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address[@addrtype='ipv6']")
        if addr is None:
            continue
        ip = addr.get('addr')
        for port in host.findall('.//port[@protocol="tcp"]'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                targets.append((ip, int(port.get('portid'))))
    return targets


def resolve_files(file_args):
    """Expand comma-separated lists and glob patterns into a deduplicated file list."""
    resolved = []
    for arg in file_args:
        for entry in arg.split(','):
            entry = entry.strip()
            if not entry:
                continue
            matches = glob_module.glob(entry)
            resolved.extend(matches if matches else [entry])
    seen = set()
    return [f for f in resolved if not (f in seen or seen.add(f))]


def load_targets(file_list, tls_ports_only=False, extra_ports=None):
    """Parse all input files and return a deduplicated list of (host, port) tuples."""
    all_targets = []
    for filepath in file_list:
        try:
            if filepath.endswith('.xml'):
                targets = parse_nmap_xml(filepath)
            else:
                targets = parse_gnmap(filepath)
            print(f'[*] Loaded {len(targets)} targets from {filepath}', file=sys.stderr)
            all_targets.extend(targets)
        except FileNotFoundError:
            print(f'[!] File not found: {filepath}', file=sys.stderr)
        except Exception as e:
            print(f'[!] Error parsing {filepath}: {e}', file=sys.stderr)

    if tls_ports_only:
        allowed = TLS_PORTS | set(STARTTLS_PORTS.keys())
        if extra_ports:
            allowed |= set(extra_ports)
        all_targets = [(h, p) for h, p in all_targets if p in allowed]

    seen = set()
    return [t for t in all_targets if not (t in seen or seen.add(t))]


# ---------------------------------------------------------------------------
# STARTTLS handlers
# ---------------------------------------------------------------------------

def _starttls_smtp(sock):
    sock.recv(1024)
    sock.sendall(b'EHLO certsiphon\r\n')
    sock.recv(4096)
    sock.sendall(b'STARTTLS\r\n')
    resp = sock.recv(1024)
    if not resp.startswith(b'220'):
        raise ValueError(f'STARTTLS rejected: {resp[:80]}')


def _starttls_imap(sock):
    sock.recv(1024)
    sock.sendall(b'a001 STARTTLS\r\n')
    resp = sock.recv(1024)
    if b'OK' not in resp:
        raise ValueError(f'STARTTLS rejected: {resp[:80]}')


def _starttls_pop3(sock):
    sock.recv(1024)
    sock.sendall(b'STLS\r\n')
    resp = sock.recv(1024)
    if not resp.startswith(b'+OK'):
        raise ValueError(f'STLS rejected: {resp[:80]}')


def _starttls_ftp(sock):
    sock.recv(1024)
    sock.sendall(b'AUTH TLS\r\n')
    resp = sock.recv(1024)
    if not resp.startswith(b'234'):
        raise ValueError(f'AUTH TLS rejected: {resp[:80]}')


STARTTLS_HANDLERS = {
    'smtp': _starttls_smtp,
    'imap': _starttls_imap,
    'pop3': _starttls_pop3,
    'ftp':  _starttls_ftp,
}


# ---------------------------------------------------------------------------
# TLS connection
# ---------------------------------------------------------------------------

def connect_and_get_cert(host, port, timeout, starttls_proto=None):
    """
    Attempt a TLS connection to host:port.
    Returns a result dict with keys: host, port, status, cert (parsed dict or None).
    Status values: 'tls', 'no_tls', 'timeout', 'starttls_error', 'ssl_error', 'connect_error'
    """
    result = {'host': host, 'port': port, 'status': None, 'cert': None}

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        result['status'] = 'timeout'
        return result
    except (ConnectionRefusedError, OSError) as e:
        result['status'] = f'connect_error: {e}'
        return result

    try:
        proto = starttls_proto or STARTTLS_PORTS.get(port)
        if proto and proto in STARTTLS_HANDLERS:
            try:
                STARTTLS_HANDLERS[proto](raw_sock)
            except Exception as e:
                raw_sock.close()
                result['status'] = f'starttls_error: {e}'
                return result

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            result['status'] = 'tls'
            result['cert'] = tls_sock.getpeercert()

    except ssl.SSLError as e:
        raw_sock.close()
        err = str(e)
        if any(x in err for x in ('WRONG_VERSION', 'NO_PROTOCOLS', 'UNKNOWN_PROTOCOL', 'WRONG_SSL')):
            result['status'] = 'no_tls'
        else:
            result['status'] = f'ssl_error: {e}'
    except Exception as e:
        result['status'] = f'error: {e}'

    return result


# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------

def is_fqdn(value):
    """Return True if value looks like a valid FQDN (wildcards allowed, bare IPs excluded)."""
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    return bool(FQDN_RE.match(value))


def extract_sld(fqdn):
    """Extract second-level domain from an FQDN. Strips leading wildcard."""
    fqdn = fqdn.lstrip('*.')
    parts = fqdn.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else fqdn


def parse_cert(cert_dict):
    """
    Extract and analyze fields from a cert dict returned by ssl.getpeercert().
    Returns a structured analysis dict.
    """
    info = {
        'cn':          None,
        'org':         None,
        'san_dns':     [],
        'san_ip':      [],
        'not_after':   None,
        'not_before':  None,
        'self_signed': False,
        'expired':     False,
        'near_expiry': False,
        'wildcard':    False,
        'fqdns':       [],
        'slds':        [],
    }

    for rdn in cert_dict.get('subject', []):
        for key, val in rdn:
            if key == 'commonName':
                info['cn'] = val
            elif key == 'organizationName':
                info['org'] = val

    info['self_signed'] = cert_dict.get('subject') == cert_dict.get('issuer')

    for san_type, san_val in cert_dict.get('subjectAltName', []):
        if san_type == 'DNS':
            info['san_dns'].append(san_val)
        elif san_type == 'IP Address':
            info['san_ip'].append(san_val)

    for date_field, key in [('notAfter', 'not_after'), ('notBefore', 'not_before')]:
        val = cert_dict.get(date_field)
        if val:
            try:
                dt = datetime.strptime(val, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                info[key] = dt.isoformat()
                if key == 'not_after':
                    now = datetime.now(timezone.utc)
                    info['expired'] = dt < now
                    info['near_expiry'] = (not info['expired'] and
                                           (dt - now).days <= NEAR_EXPIRY_DAYS)
            except ValueError:
                pass

    candidates = info['san_dns'] + ([info['cn']] if info['cn'] else [])
    fqdns = set()
    for val in candidates:
        if is_fqdn(val):
            fqdns.add(val)
            if val.startswith('*.'):
                info['wildcard'] = True

    info['fqdns'] = sorted(fqdns)
    info['slds']  = sorted({extract_sld(f) for f in info['fqdns']})
    return info


# ---------------------------------------------------------------------------
# Scan worker
# ---------------------------------------------------------------------------

def scan_target(host, port, timeout, starttls_proto, rate_lock, rate_delay):
    if rate_delay > 0 and rate_lock:
        with rate_lock:
            time.sleep(rate_delay)

    result = connect_and_get_cert(host, port, timeout, starttls_proto)
    result['cert_info'] = None
    if result['status'] == 'tls' and result['cert']:
        result['cert_info'] = parse_cert(result['cert'])
    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_result(result, verbose, quiet):
    """Print a single host result to stdout."""
    host, port, status = result['host'], result['port'], result['status']

    if status == 'timeout':
        if verbose:
            print(f'[-] {host}:{port}  TIMEOUT')
        return
    if status == 'no_tls':
        if verbose:
            print(f'[-] {host}:{port}  NO TLS')
        return
    if status != 'tls':
        if verbose:
            print(f'[!] {host}:{port}  {status}')
        return

    info = result.get('cert_info')
    if not info or quiet:
        return

    flags = []
    if info['self_signed']: flags.append('SELF-SIGNED')
    if info['expired']:     flags.append('EXPIRED')
    if info['near_expiry']: flags.append('NEAR-EXPIRY')
    if info['wildcard']:    flags.append('WILDCARD')
    flag_str = '  [' + ' '.join(flags) + ']' if flags else ''

    print(f'\n[+] {host}:{port}{flag_str}')
    if info['org']:      print(f"    Org  : {info['org']}")
    if info['cn']:       print(f"    CN   : {info['cn']}")
    if info['san_dns']:  print(f"    SANs : {', '.join(info['san_dns'])}")
    if info['san_ip']:   print(f"    IPs  : {', '.join(info['san_ip'])}")
    if info['not_after']:print(f"    Exp  : {info['not_after']}")


def matches_flags(cert_info, required_flags):
    """Return True if cert_info satisfies all required flag filters."""
    if not required_flags or not cert_info:
        return True
    flag_map = {
        'expired':     cert_info.get('expired', False),
        'near-expiry': cert_info.get('near_expiry', False),
        'self-signed': cert_info.get('self_signed', False),
        'wildcard':    cert_info.get('wildcard', False),
    }
    return any(flag_map.get(f, False) for f in required_flags)


def collect_domains(results, wildcards_only=False):
    """Aggregate unique FQDNs and SLDs across all results."""
    fqdns, slds = set(), set()
    for r in results:
        info = r.get('cert_info')
        if not info:
            continue
        for fqdn in info.get('fqdns', []):
            if wildcards_only and not fqdn.startswith('*.'):
                continue
            fqdns.add(fqdn)
            slds.add(extract_sld(fqdn))
    return sorted(fqdns), sorted(slds)


def build_output(results, args, fqdns, slds):
    """Format final output based on selected output mode."""
    if args.json:
        serializable = []
        for r in results:
            entry = {k: v for k, v in r.items() if k not in ('cert',)}
            serializable.append(entry)
        return json.dumps({'results': serializable, 'fqdns': fqdns, 'slds': slds}, indent=2)

    if args.csv:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['host', 'port', 'status', 'cn', 'org', 'fqdns', 'slds', 'flags'])
        for r in results:
            info = r.get('cert_info') or {}
            flags = [f for f, v in {
                'expired':     info.get('expired'),
                'near-expiry': info.get('near_expiry'),
                'self-signed': info.get('self_signed'),
                'wildcard':    info.get('wildcard'),
            }.items() if v]
            writer.writerow([
                r['host'], r['port'], r['status'],
                info.get('cn', ''), info.get('org', ''),
                '|'.join(info.get('fqdns', [])),
                '|'.join(info.get('slds', [])),
                '|'.join(flags),
            ])
        return buf.getvalue()

    if args.list:
        return ','.join(fqdns)

    if args.sld:
        return '\n'.join(slds)

    lines = []
    if not args.quiet:
        lines.append(f'\n[*] Unique FQDNs ({len(fqdns)}):')
        for f in fqdns:
            lines.append(f'    {f}')
        lines.append(f'\n[*] Unique SLDs ({len(slds)}):')
        for s in slds:
            lines.append(f'    {s}')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='certsiphon.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Siphon FQDNs and second-level domains from TLS certificates\n'
            'across hosts and ports discovered in nmap scan output files.\n\n'
            'Supports grepable (.gnmap) and XML (.xml) nmap formats.\n'
            'Attempts direct TLS and STARTTLS connections depending on port.\n'
            'Extracts Common Name (CN), Subject Alternative Names (SANs),\n'
            'and Organization (O=) fields; validates and deduplicates FQDNs.'
        ),
        epilog=(
            'Output Modes:\n'
            '  Default         Per-host cert details + unique FQDN/SLD summary\n'
            '  -l / --list     Single comma-separated line of unique FQDNs\n'
            '  -s / --sld      Unique second-level domains, one per line\n'
            '  --json          Full structured JSON output\n'
            '  --csv           CSV: host,port,status,cn,org,fqdns,slds,flags\n\n'
            'Examples:\n'
            '  # Single file\n'
            '  %(prog)s scan.gnmap\n\n'
            '  # Mix of XML and grepable\n'
            '  %(prog)s internal.xml dmz.gnmap\n\n'
            '  # Glob pattern (quote to prevent shell expansion)\n'
            '  %(prog)s "tcp*.gnmap"\n\n'
            '  # Comma-separated list\n'
            '  %(prog)s scan1.gnmap,scan2.gnmap,scan3.xml\n\n'
            '  # Faster scan with more threads and longer timeout\n'
            '  %(prog)s scan.gnmap -t 50 --timeout 5\n\n'
            '  # Only probe known TLS/STARTTLS ports\n'
            '  %(prog)s scan.gnmap --tls-ports-only\n\n'
            '  # Force STARTTLS smtp on a non-standard port\n'
            '  %(prog)s scan.gnmap --starttls smtp --extra-ports 2525\n\n'
            '  # Rate-limited scan (0.5s delay between connections)\n'
            '  %(prog)s scan.gnmap --rate-delay 0.5\n\n'
            '  # Find expired or self-signed certs only\n'
            '  %(prog)s scan.gnmap --flags expired self-signed\n\n'
            '  # Wildcard certs only, written to file\n'
            '  %(prog)s scan.gnmap --wildcards-only -o wildcards.txt\n\n'
            '  # Single-line FQDN list (pipe-friendly, e.g. into aquatone)\n'
            '  %(prog)s scan.gnmap -l\n\n'
            '  # SLD list to file\n'
            '  %(prog)s scan.gnmap -s -o slds.txt\n\n'
            '  # Full JSON output\n'
            '  %(prog)s scan.gnmap --json -o results.json\n\n'
            '  # CSV for import into spreadsheets or SIEM\n'
            '  %(prog)s scan.gnmap --csv -o results.csv\n\n'
            '  # Verbose: show timeouts and non-TLS services\n'
            '  %(prog)s scan.gnmap -v\n\n'
            '  # Quiet: suppress per-host output, summary only\n'
            '  %(prog)s scan.gnmap -q\n'
        )
    )

    # --- Input ---
    input_grp = parser.add_argument_group(
        'Input',
        'One or more nmap output files. Supports grepable (.gnmap) and XML (.xml) formats.'
    )
    input_grp.add_argument(
        'files', nargs='+', metavar='FILE',
        help=(
            'nmap output file(s) to process.\n'
            'Accepts: single file, space-separated list, comma-separated list,\n'
            'or glob pattern (e.g. "tcp*.gnmap" — quote to prevent shell expansion).\n'
            'File type is auto-detected by extension (.xml vs everything else → gnmap).'
        )
    )

    # --- Connectivity ---
    conn_grp = parser.add_argument_group(
        'Connectivity',
        'Control how certsiphon connects to each host:port target.'
    )
    conn_grp.add_argument(
        '--timeout', type=float, default=3.0, metavar='SEC',
        help='TCP connection timeout per host:port in seconds. (default: 3.0)'
    )
    conn_grp.add_argument(
        '-t', '--threads', type=int, default=10, metavar='N',
        help=(
            'Number of concurrent scanning threads. Increase for large host lists;\n'
            'decrease on slow networks or to reduce noise. (default: 10)'
        )
    )
    conn_grp.add_argument(
        '--rate-delay', type=float, default=0.0, metavar='SEC',
        help=(
            'Insert a delay of SEC seconds between each connection attempt.\n'
            'Useful for evading IDS/IPS rate-based detection. (default: 0, disabled)'
        )
    )
    conn_grp.add_argument(
        '--starttls', choices=['smtp', 'imap', 'pop3', 'ftp'], metavar='PROTO',
        help=(
            'Force STARTTLS negotiation using the specified application protocol\n'
            'before upgrading to TLS. Auto-detected for standard ports:\n'
            '  25, 587 → smtp    143 → imap    110 → pop3    21 → ftp\n'
            'Use this flag to override auto-detection or force STARTTLS on\n'
            'non-standard ports. Choices: smtp, imap, pop3, ftp'
        )
    )
    conn_grp.add_argument(
        '--tls-ports-only', action='store_true',
        help=(
            'Skip ports that are not in the known TLS or STARTTLS port lists.\n'
            f'Direct TLS ports  : {sorted(TLS_PORTS)}\n'
            f'STARTTLS ports    : {sorted(STARTTLS_PORTS.keys())}\n'
            'Use --extra-ports to extend this list without scanning everything.'
        )
    )
    conn_grp.add_argument(
        '--extra-ports', type=str, metavar='PORTS',
        help=(
            'Comma-separated list of additional ports to include when\n'
            '--tls-ports-only is active. Has no effect without --tls-ports-only.\n'
            'Example: --extra-ports 8444,9444,10443'
        )
    )

    # --- Certificate Analysis ---
    cert_grp = parser.add_argument_group(
        'Certificate Analysis',
        'Control what is extracted and flagged from each certificate.'
    )
    cert_grp.add_argument(
        '--wildcards-only', action='store_true',
        help=(
            'Only include wildcard FQDNs (e.g. *.example.com) in output.\n'
            'Useful for identifying broad-scope certs that reveal internal\n'
            'naming conventions or multi-tenant infrastructure.'
        )
    )
    cert_grp.add_argument(
        '--flags', nargs='+',
        choices=['expired', 'near-expiry', 'self-signed', 'wildcard'],
        metavar='FLAG',
        help=(
            'Filter output to hosts where the leaf cert has at least one of\n'
            'the specified flags. Multiple flags use OR logic.\n'
            'Choices:\n'
            '  expired      Certificate notAfter is in the past\n'
            f'  near-expiry  Expiring within {NEAR_EXPIRY_DAYS} days\n'
            '  self-signed  Subject and Issuer fields are identical\n'
            '  wildcard     CN or any SAN entry is a wildcard (*.domain)\n'
            'Example: --flags expired self-signed'
        )
    )

    # --- Output ---
    out_grp = parser.add_argument_group(
        'Output',
        'Control output format and destination. Modes are mutually exclusive;\n'
        'if none are specified, per-host details and a domain summary are printed.'
    )
    out_grp.add_argument(
        '-l', '--list', action='store_true',
        help=(
            'Output a single comma-separated line of all unique FQDNs.\n'
            'Suppresses all other output. Pipe-friendly.\n'
            'Example: nmap -iL $(certsiphon.py scan.gnmap -l) ...'
        )
    )
    out_grp.add_argument(
        '-s', '--sld', action='store_true',
        help=(
            'Output unique second-level domains only, one per line.\n'
            'Suppresses all other output.\n'
            'Note: uses last-two-labels heuristic; multi-part TLDs (e.g.\n'
            '.co.uk) will return the TLD+1 portion only (co.uk), not TLD+2.'
        )
    )
    out_grp.add_argument(
        '--json', action='store_true',
        help=(
            'Output full results as a JSON document.\n'
            'Includes per-host status, all cert fields, flags, FQDNs, SLDs,\n'
            'and a top-level aggregated fqdns/slds list.\n'
            'Use with -o to write to file.'
        )
    )
    out_grp.add_argument(
        '--csv', action='store_true',
        help=(
            'Output results as CSV with columns:\n'
            '  host, port, status, cn, org, fqdns, slds, flags\n'
            'FQDNs, SLDs, and flags are pipe-delimited within their columns.\n'
            'Use with -o to write to file for import into spreadsheets or SIEM.'
        )
    )
    out_grp.add_argument(
        '-o', '--output', metavar='FILE',
        help=(
            'Write output to FILE instead of stdout.\n'
            'Informational messages ([*] / [!]) always go to stderr regardless.'
        )
    )
    out_grp.add_argument(
        '-v', '--verbose', action='store_true',
        help=(
            'Show all connection attempts in output, including:\n'
            '  timeouts, refused connections, non-TLS services, SSL errors.\n'
            'By default only successful TLS connections are shown.'
        )
    )
    out_grp.add_argument(
        '-q', '--quiet', action='store_true',
        help=(
            'Suppress per-host detail output. Only the final aggregated\n'
            'FQDN and SLD summary is printed. Ignored in -l, -s, --json,\n'
            'and --csv modes which manage their own output format.'
        )
    )

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # --- Resolve inputs ---
    file_list = resolve_files(args.files)
    if not file_list:
        print('[!] No files matched.', file=sys.stderr)
        sys.exit(1)

    extra_ports = None
    if args.extra_ports:
        try:
            extra_ports = [int(p.strip()) for p in args.extra_ports.split(',')]
        except ValueError:
            print('[!] --extra-ports must be comma-separated integers.', file=sys.stderr)
            sys.exit(1)

    targets = load_targets(file_list, tls_ports_only=args.tls_ports_only, extra_ports=extra_ports)
    if not targets:
        print('[!] No targets found in provided files.', file=sys.stderr)
        sys.exit(1)

    print(f'[*] {len(targets)} host:port targets | {args.threads} threads | timeout {args.timeout}s',
          file=sys.stderr)

    # --- Scan ---
    rate_lock = threading.Lock() if args.rate_delay > 0 else None
    all_results = []
    starttls_proto = args.starttls if args.starttls else None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_target, host, port,
                args.timeout, starttls_proto, rate_lock, args.rate_delay
            ): (host, port)
            for host, port in targets
        }
        for future in as_completed(futures):
            result = future.result()
            info = result.get('cert_info')

            if args.flags and not matches_flags(info, args.flags):
                continue

            all_results.append(result)

            if not any([args.list, args.sld, args.json, args.csv]):
                print_result(result, verbose=args.verbose, quiet=args.quiet)

    # --- Aggregate and format ---
    fqdns, slds = collect_domains(all_results, wildcards_only=args.wildcards_only)
    output = build_output(all_results, args, fqdns, slds)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output + '\n')
        print(f'[*] Output written to {args.output}', file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
