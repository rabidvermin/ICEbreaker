#!/usr/bin/env python3
"""httpsiphon — Detect HTTP and HTTPS services across nmap scan output."""

import argparse
import csv
import io
import json
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from xml.etree import ElementTree
import glob as glob_module

BANNER = r"""
  +------------------------------------------------------------------+
  | GET / HTTP/1.1 200 OK Server: nginx X-Powered-By: PHP/8.1       |
  | 301 Location: https:// Content-Type: text/html 403 Forbidden    |
  | WWW-Authenticate: Basic HEAD HTTP/1.0 500 X-Frame-Options: DENY |
  | Strict-Transport-Security 401 Unauthorized Content-Length: 1337 |
  +-----------------------------------+------------------------------+
                                      |  )))
                                      |  )))
                                      |  )))
                                      v
  +-----------------------------------+------------------------------+
  |                                                                  |
  |                   h t t p s i p h o n                           |
  +------------------------------------------------------------------+
"""

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
]

HEAD_REQUEST = 'HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'
GET_REQUEST  = 'GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'


# ---------------------------------------------------------------------------
# File parsing  (identical pattern to certsiphon)
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


def load_targets(file_list):
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
    seen = set()
    return [t for t in all_targets if not (t in seen or seen.add(t))]


# ---------------------------------------------------------------------------
# HTML title parser
# ---------------------------------------------------------------------------

class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_title = False
        self.title = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'title':
            self._in_title = True

    def handle_data(self, data):
        if self._in_title and self.title is None:
            self.title = data.strip()

    def handle_endtag(self, tag):
        if tag.lower() == 'title':
            self._in_title = False


def extract_title(body_bytes):
    """Extract <title> from raw HTML bytes. Returns None if not found."""
    try:
        html = body_bytes.decode('utf-8', errors='replace')
        parser = TitleParser()
        parser.feed(html[:8192])
        return parser.title
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def parse_http_response(raw):
    """
    Parse a raw HTTP response byte string.
    Returns (status_code, headers_dict, body_bytes) or None if not valid HTTP.
    """
    try:
        header_end = raw.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = raw.find(b'\n\n')
        if header_end == -1:
            return None

        header_section = raw[:header_end].decode('utf-8', errors='replace')
        body = raw[header_end + 4:]

        lines = header_section.split('\r\n') if '\r\n' in header_section else header_section.split('\n')
        status_line = lines[0].strip()

        if not status_line.startswith('HTTP/'):
            return None

        parts = status_line.split(None, 2)
        status_code = int(parts[1]) if len(parts) >= 2 else 0

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()

        return status_code, headers, body
    except Exception:
        return None


def probe_http(host, port, timeout, use_ssl=False, grab_title=False):
    """
    Send a raw HTTP HEAD (and optionally GET) to host:port.
    Returns a result dict or None if no valid HTTP response.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return {'status': 'timeout'}
    except (ConnectionRefusedError, OSError) as e:
        return {'status': f'connect_error: {e}'}

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        request = HEAD_REQUEST.format(host=host).encode()
        sock.sendall(request)

        raw = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                break

        sock.close()
    except ssl.SSLError:
        return None
    except Exception:
        return None

    parsed = parse_http_response(raw)
    if not parsed:
        return None

    status_code, headers, _ = parsed
    proto = 'https' if use_ssl else 'http'
    url = f'{proto}://{host}:{port}'

    result = {
        'status':       'ok',
        'protocol':     proto,
        'url':          url,
        'host':         host,
        'port':         port,
        'status_code':  status_code,
        'server':       headers.get('server'),
        'content_type': headers.get('content-type'),
        'location':     headers.get('location'),
        'powered_by':   headers.get('x-powered-by'),
        'auth':         headers.get('www-authenticate'),
        'title':        None,
        'missing_sec_headers': [h for h in SECURITY_HEADERS if h not in headers],
        'flags':        [],
    }

    # Flag notable conditions
    if status_code in (301, 302, 303, 307, 308):
        result['flags'].append('redirect')
    if status_code == 401:
        result['flags'].append('auth-required')
    if status_code == 403:
        result['flags'].append('forbidden')
    if result['missing_sec_headers']:
        result['flags'].append('missing-sec-headers')
    if not use_ssl:
        result['flags'].append('plaintext')

    # Optional title grab via GET
    if grab_title:
        try:
            sock2 = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                sock2 = ctx.wrap_socket(sock2, server_hostname=host)
            sock2.sendall(GET_REQUEST.format(host=host).encode())
            raw2 = b''
            while True:
                chunk = sock2.recv(4096)
                if not chunk:
                    break
                raw2 += chunk
                if len(raw2) > 131072:
                    break
            sock2.close()
            parsed2 = parse_http_response(raw2)
            if parsed2:
                result['title'] = extract_title(parsed2[2])
        except Exception:
            pass

    return result


def scan_target(host, port, timeout, grab_title, rate_lock, rate_delay):
    """
    Probe host:port for HTTP, then HTTPS if HTTP not found.
    Returns a result dict with status and all extracted data.
    """
    if rate_delay > 0 and rate_lock:
        with rate_lock:
            time.sleep(rate_delay)

    # Try plain HTTP first
    result = probe_http(host, port, timeout, use_ssl=False, grab_title=grab_title)
    if result and result.get('status') == 'ok':
        return result

    # Preserve connection errors without retrying SSL
    if result and result['status'] not in ('ok', None):
        conn_status = result['status']
    else:
        conn_status = None

    # Try HTTPS
    result = probe_http(host, port, timeout, use_ssl=True, grab_title=grab_title)
    if result and result.get('status') == 'ok':
        return result

    # Neither HTTP nor HTTPS
    return {
        'status':      conn_status or 'no_http',
        'protocol':    None,
        'url':         None,
        'host':        host,
        'port':        port,
        'status_code': None,
        'server':      None,
        'content_type':None,
        'location':    None,
        'powered_by':  None,
        'auth':        None,
        'title':       None,
        'missing_sec_headers': [],
        'flags':       [],
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_result(result, verbose, quiet):
    """Print a single result to stdout in default mode."""
    status = result['status']

    if status != 'ok':
        if verbose:
            print(f"[-] {result['host']}:{result['port']}  {status}")
        return

    if quiet:
        return

    url   = result['url']
    code  = result['status_code']
    flags = result['flags']

    line = f"{url}  [{code}]"
    if result['server']:
        line += f"  {result['server']}"
    if result['title']:
        line += f"  \"{result['title']}\""
    if result['location']:
        line += f"  -> {result['location']}"
    if flags:
        line += f"  ({', '.join(flags)})"

    print(line)


def build_output(results, args):
    """Format final output based on selected mode."""
    ok = [r for r in results if r['status'] == 'ok']

    if args.json:
        return json.dumps({'results': results, 'total': len(ok)}, indent=2)

    if args.csv:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['url', 'host', 'port', 'protocol', 'status_code',
                         'server', 'title', 'location', 'powered_by', 'auth', 'flags'])
        for r in ok:
            writer.writerow([
                r['url'], r['host'], r['port'], r['protocol'],
                r['status_code'], r['server'] or '', r['title'] or '',
                r['location'] or '', r['powered_by'] or '', r['auth'] or '',
                '|'.join(r['flags']),
            ])
        return buf.getvalue()

    if args.list:
        return ','.join(r['url'] for r in ok)

    # Default: one URL per line
    return '\n'.join(r['url'] for r in ok)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='httpsiphon.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Detect HTTP and HTTPS services across hosts and ports discovered\n'
            'in nmap scan output files. Uses raw TCP sockets — no external tools.\n\n'
            'For each host:port, attempts a plain HTTP probe first. If no valid\n'
            'HTTP response is received, retries with TLS (HTTPS). Extracts status\n'
            'codes, server headers, redirects, auth requirements, and optionally\n'
            'page titles.'
        ),
        epilog=(
            'Output Modes:\n'
            '  Default         One URL per line for all discovered HTTP/HTTPS services\n'
            '  -l / --list     Single comma-separated line of all URLs\n'
            '  --json          Full structured JSON output\n'
            '  --csv           CSV: url,host,port,protocol,status_code,server,...\n\n'
            'Examples:\n'
            '  # Default: one URL per line\n'
            '  %(prog)s scan.gnmap\n\n'
            '  # Mix of XML and grepable input\n'
            '  %(prog)s internal.xml dmz.gnmap\n\n'
            '  # Glob pattern\n'
            '  %(prog)s "tcp*.gnmap"\n\n'
            '  # Faster scan with more threads\n'
            '  %(prog)s scan.gnmap -t 50 --timeout 5\n\n'
            '  # Also grab page titles (uses GET, slower)\n'
            '  %(prog)s scan.gnmap --grab-title\n\n'
            '  # Only show HTTPS services\n'
            '  %(prog)s scan.gnmap --https-only\n\n'
            '  # Only show plain HTTP services\n'
            '  %(prog)s scan.gnmap --http-only\n\n'
            '  # Filter by status code\n'
            '  %(prog)s scan.gnmap --status 200 401 403\n\n'
            '  # Flag services missing security headers\n'
            '  %(prog)s scan.gnmap --missing-headers\n\n'
            '  # Rate-limited scan\n'
            '  %(prog)s scan.gnmap --rate-delay 0.5\n\n'
            '  # Comma-separated URL list (pipe-friendly)\n'
            '  %(prog)s scan.gnmap -l\n\n'
            '  # Full JSON to file\n'
            '  %(prog)s scan.gnmap --json -o results.json\n\n'
            '  # CSV export\n'
            '  %(prog)s scan.gnmap --csv -o results.csv\n\n'
            '  # Verbose: show timeouts and non-HTTP ports\n'
            '  %(prog)s scan.gnmap -v\n\n'
            '  # Quiet: suppress per-host output\n'
            '  %(prog)s scan.gnmap -q -o urls.txt\n'
        )
    )

    # --- Input ---
    input_grp = parser.add_argument_group(
        'Input',
        'nmap output files to process. Supports grepable (.gnmap) and XML (.xml).'
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
        'Control how httpsiphon connects to each host:port.'
    )
    conn_grp.add_argument(
        '--timeout', type=float, default=3.0, metavar='SEC',
        help='TCP connection timeout per host:port in seconds. (default: 3.0)'
    )
    conn_grp.add_argument(
        '-t', '--threads', type=int, default=10, metavar='N',
        help='Number of concurrent scanning threads. (default: 10)'
    )
    conn_grp.add_argument(
        '--rate-delay', type=float, default=0.0, metavar='SEC',
        help=(
            'Delay in seconds between each connection attempt.\n'
            'Useful for evading rate-based IDS/IPS detection. (default: 0, disabled)'
        )
    )

    # --- Detection ---
    detect_grp = parser.add_argument_group(
        'Detection',
        'Control what httpsiphon looks for and extracts.'
    )
    detect_grp.add_argument(
        '--grab-title', action='store_true',
        help=(
            'Issue a GET request (in addition to HEAD) to extract the HTML <title> tag.\n'
            'Slower — doubles the number of requests per host. Useful for quick\n'
            'application fingerprinting without a full spider.'
        )
    )
    detect_grp.add_argument(
        '--http-only', action='store_true',
        help='Only report services that responded to plain HTTP. Skips HTTPS results.'
    )
    detect_grp.add_argument(
        '--https-only', action='store_true',
        help='Only report services that responded to HTTPS. Skips plain HTTP results.'
    )
    detect_grp.add_argument(
        '--status', nargs='+', type=int, metavar='CODE',
        help=(
            'Filter output to results matching one or more HTTP status codes.\n'
            'Example: --status 200 401 403'
        )
    )
    detect_grp.add_argument(
        '--missing-headers', action='store_true',
        help=(
            'Only show services that are missing one or more security headers.\n'
            f'Checked headers: {", ".join(SECURITY_HEADERS)}'
        )
    )

    # --- Output ---
    out_grp = parser.add_argument_group(
        'Output',
        'Control output format and destination.\n'
        'Default output is one URL per line for all discovered HTTP/HTTPS services.'
    )
    out_grp.add_argument(
        '-l', '--list', action='store_true',
        help=(
            'Output all discovered URLs as a single comma-separated line.\n'
            'Pipe-friendly. Suppresses all other output.'
        )
    )
    out_grp.add_argument(
        '--json', action='store_true',
        help=(
            'Output full results as JSON.\n'
            'Includes all extracted fields for every host:port probed.'
        )
    )
    out_grp.add_argument(
        '--csv', action='store_true',
        help=(
            'Output results as CSV with columns:\n'
            'url, host, port, protocol, status_code, server, title,\n'
            'location, powered_by, auth, flags'
        )
    )
    out_grp.add_argument(
        '-o', '--output', metavar='FILE',
        help=(
            'Write output to FILE instead of stdout.\n'
            'Informational messages always go to stderr.'
        )
    )
    out_grp.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show all probed ports including timeouts and non-HTTP services.'
    )
    out_grp.add_argument(
        '-q', '--quiet', action='store_true',
        help=(
            'Suppress per-host output during scanning.\n'
            'Final URL list is still written to stdout or -o file.'
        )
    )

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.http_only and args.https_only:
        print('[!] --http-only and --https-only are mutually exclusive.', file=sys.stderr)
        sys.exit(1)

    # --- Load targets ---
    file_list = resolve_files(args.files)
    if not file_list:
        print('[!] No files matched.', file=sys.stderr)
        sys.exit(1)

    targets = load_targets(file_list)
    if not targets:
        print('[!] No targets found in provided files.', file=sys.stderr)
        sys.exit(1)

    print(f'[*] {len(targets)} host:port targets | {args.threads} threads | timeout {args.timeout}s',
          file=sys.stderr)

    # --- Scan ---
    rate_lock = threading.Lock() if args.rate_delay > 0 else None
    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_target, host, port,
                args.timeout, args.grab_title, rate_lock, args.rate_delay
            ): (host, port)
            for host, port in targets
        }
        for future in as_completed(futures):
            result = future.result()

            # Apply filters
            if result['status'] == 'ok':
                if args.http_only and result['protocol'] != 'http':
                    continue
                if args.https_only and result['protocol'] != 'https':
                    continue
                if args.status and result['status_code'] not in args.status:
                    continue
                if args.missing_headers and not result['missing_sec_headers']:
                    continue

            all_results.append(result)

            if not any([args.list, args.json, args.csv]):
                print_result(result, verbose=args.verbose, quiet=args.quiet)

    # --- Format and write output ---
    output = build_output(all_results, args)

    ok_count = sum(1 for r in all_results if r['status'] == 'ok')
    print(f'[*] Found {ok_count} HTTP/HTTPS services.', file=sys.stderr)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output + '\n')
        print(f'[*] Output written to {args.output}', file=sys.stderr)
    else:
        if output:
            print(output)


if __name__ == '__main__':
    main()
