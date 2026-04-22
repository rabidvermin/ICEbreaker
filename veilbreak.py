#!/usr/bin/env python3
"""veilbreak.py — Web content enumeration at scale, powered by feroxbuster."""

import argparse
import os
import re
import shutil
import signal
import socket
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from subprocess import Popen, DEVNULL
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
🔍 ═══════════════════════════════════════════ 🔍

     ▓▓░░▓▓░░  V E I L B R E A K  ░░▓▓░░▓▓

        web content enumeration at scale

  9c:3a:ff  7a:b2  ░░░ /admin          [200]
  0x4f:1e   3b:9c  ░░░ /login          [200]
  b2:7a:0x  ff:4e  ░░░ /api/v1         [403]
  3a:9c:b2  1e:7a  ░░░ /.env           [200] 🔥
  4f:0x:3f  9c:ff  ░░░ /config.php     [200] 🔥
  ─────────────────────────────────────────────
  7a:b2:1e  0x:3a  ░░░ /wp-admin       [301]
  ff:4e:9c  7a:b2  ░░░ /backup.zip     [200] 🔥
  0x:3f:4f  1e:ff  ░░░ /api/swagger    [200]
  9c:1e:b2  3a:0x  ░░░ /uploads        [403]
  3b:ff:7a  4e:9c  ░░░ /.git/config    [200] 🔥
  ─────────────────────────────────────────────

       web content enumeration at scale
     powered by 🔥 feroxbuster 🔥

🔍 ═══════════════════════════════════════════ 🔍
"""

EXTENDED_HELP = """
EXTENDED HELP — veilbreak.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DESCRIPTION
  veilbreak reads a list of HTTP/HTTPS URLs (e.g. from httpsiphon),
  resolves each hostname to an IP address, then launches feroxbuster
  jobs concurrently — with the constraint that only one job runs
  against any given IP at a time to avoid overloading a single host.

  Jobs run headlessly in the background. veilbreak monitors each job
  for timeouts, anomalous responses, and unexpected failures, killing
  and reporting any that trigger detection thresholds.

  One output file is written per job into a timestamped directory.

PREREQUISITES
  feroxbuster must be installed and in PATH.
    Install: cargo install feroxbuster
    Or:      https://github.com/epi052/feroxbuster
    Distro:  apt install feroxbuster  (Kali/Debian)

INPUT
  URLs are read one per line from a file (--urls) or stdin.
  Compatible with httpsiphon default output:

    python3 httpsiphon.py scan.gnmap | python3 veilbreak.py
    python3 veilbreak.py --urls urls.txt

IP-BASED CONCURRENCY
  veilbreak resolves every URL's hostname to an IP before scanning.
  The scheduler ensures only one feroxbuster job runs per IP at a
  time. If all remaining queued URLs map to IPs already in-flight,
  the scheduler waits until a slot opens.

  MAX_JOBS controls the total number of simultaneous jobs globally.
  Effective concurrency = min(MAX_JOBS, number of distinct IPs).

ANOMALY / WILDCARD DETECTION
  Each running job's output is monitored every POLL_INTERVAL seconds.
  If WILDCARD_MIN_SAMPLE or more responses have been collected and
  WILDCARD_THRESHOLD% or more share the same HTTP status code, the
  job is killed and flagged as anomalous. This catches:
    - Wildcard/catch-all response configurations
    - Tarpits returning the same response to everything
    - WAFs blocking all requests with the same code

JOB TIMEOUT
  Each job has a hard timeout of JOB_TIMEOUT seconds. Jobs that
  exceed this are killed and marked as timed-out. Partial output
  is preserved.

OUTPUT STRUCTURE
  OUTPUT_DIR/
    YYYYMMDD-HHMMSS/              <- one directory per veilbreak run
      http_10.1.1.1_80.txt        <- one file per job
      https_example.com_443.txt
      https_api.corp.lan_8443.txt

CONFIGURATION FILE
  Default: veilbreak.conf (same directory as script)
  Format:  KEY = VALUE, one per line, # for comments

  Keys:
    MAX_JOBS            Max concurrent feroxbuster jobs (default: 5)
    WORDLIST            Path to wordlist file
    DEPTH               Max recursion depth (default: 3)
    THREADS             Threads per feroxbuster job (default: 50)
    JOB_TIMEOUT         Seconds before a job is killed (default: 300)
    STATUS_CODES        Comma-separated valid HTTP codes
    EXTENSIONS          Comma-separated extensions to enumerate
    FOLLOW_REDIRECTS    yes/no
    USER_AGENT          HTTP user agent string
    WILDCARD_THRESHOLD  % threshold for anomaly detection (default: 90)
    WILDCARD_MIN_SAMPLE Min responses before anomaly check (default: 20)
    POLL_INTERVAL       Scheduler poll interval in seconds (default: 2)
    OUTPUT_DIR          Base output directory
    EXTRA_FLAGS         Additional feroxbuster flags (raw string)

EXAMPLES
  # Run against httpsiphon output
  python3 httpsiphon.py scan.gnmap | python3 veilbreak.py

  # From a URL file
  python3 veilbreak.py --urls urls.txt

  # Custom wordlist and depth
  python3 veilbreak.py --urls urls.txt --wordlist /path/to/list.txt --depth 5

  # More concurrent jobs, longer timeout
  python3 veilbreak.py --urls urls.txt --jobs 10 --timeout 600

  # Dry run — see all feroxbuster commands without executing
  python3 veilbreak.py --urls urls.txt --dry-run

  # Pipe through proxy (via EXTRA_FLAGS in config or --extra-flags)
  python3 veilbreak.py --urls urls.txt --extra-flags "--insecure --proxy http://127.0.0.1:8080"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULTS = {
    'MAX_JOBS':            '5',
    'WORDLIST':            '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    'DEPTH':               '3',
    'THREADS':             '50',
    'JOB_TIMEOUT':         '300',
    'STATUS_CODES':        '200,201,204,301,302,307,401,403,405',
    'EXTENSIONS':          'php,html,js,txt,json,xml,bak,zip',
    'FOLLOW_REDIRECTS':    'yes',
    'USER_AGENT':          'Mozilla/5.0 (compatible; veilbreak/1.0)',
    'WILDCARD_THRESHOLD':  '90',
    'WILDCARD_MIN_SAMPLE': '20',
    'POLL_INTERVAL':       '2',
    'OUTPUT_DIR':          './veilbreak-output',
    'EXTRA_FLAGS':         '',
}


def load_config(path):
    cfg = dict(DEFAULTS)
    if not os.path.exists(path):
        print(f'{YELLOW}[!] Config not found: {path} — using built-in defaults.{RESET}',
              file=sys.stderr)
        return cfg
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                print(f'{YELLOW}[!] Skipping malformed config line {lineno}: {line}{RESET}',
                      file=sys.stderr)
                continue
            key, _, val = line.partition('=')
            cfg[key.strip().upper()] = val.strip()
    return cfg


def cfg_int(cfg, key):
    try:
        return int(cfg[key])
    except (ValueError, KeyError):
        return int(DEFAULTS[key])


def cfg_bool(cfg, key):
    return cfg.get(key, '').lower() in ('yes', 'true', '1')


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

def check_feroxbuster():
    if not shutil.which('feroxbuster'):
        print(f'{RED}{BOLD}[!] feroxbuster not found in PATH.{RESET}', file=sys.stderr)
        print(f'    Install options:', file=sys.stderr)
        print(f'      cargo install feroxbuster', file=sys.stderr)
        print(f'      apt install feroxbuster  (Kali/Debian)', file=sys.stderr)
        print(f'      https://github.com/epi052/feroxbuster', file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# URL / hostname resolution
# ---------------------------------------------------------------------------

def parse_url(url):
    """Return (scheme, hostname, port) from a URL string."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    port = parsed.port
    if port is None:
        port = 443 if scheme == 'https' else 80
    return scheme, hostname, port


def resolve_host(hostname):
    """Resolve hostname to IP. Returns IP string or None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def resolve_urls(urls, verbose=False):
    """
    Resolve all URLs to IPs in parallel.
    Returns list of (url, scheme, hostname, port, ip) tuples.
    Prints warnings for failed resolutions and skips them.
    """
    print(f'[*] Resolving {len(urls)} hostnames...', file=sys.stderr)
    resolved = []
    failed = []

    def resolve(url):
        scheme, hostname, port = parse_url(url)
        ip = resolve_host(hostname)
        return url, scheme, hostname, port, ip

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(resolve, url): url for url in urls}
        for future in as_completed(futures):
            url, scheme, hostname, port, ip = future.result()
            if ip is None:
                failed.append(url)
                print(f'{YELLOW}[!] DNS resolution failed: {url} — skipping.{RESET}',
                      file=sys.stderr)
            else:
                resolved.append((url, scheme, hostname, port, ip))
                if verbose:
                    print(f'[*] Resolved: {hostname} → {ip}', file=sys.stderr)

    print(f'[*] Resolved {len(resolved)} URLs. Skipped {len(failed)}.', file=sys.stderr)
    return resolved, failed


# ---------------------------------------------------------------------------
# Feroxbuster command builder
# ---------------------------------------------------------------------------

def build_command(url, cfg, output_file):
    """Build the feroxbuster command list for a given URL."""
    cmd = [
        'feroxbuster',
        '--url',        url,
        '--depth',      cfg['DEPTH'],
        '--threads',    cfg['THREADS'],
        '--wordlist',   cfg['WORDLIST'],
        '--status-codes', cfg['STATUS_CODES'],
        '--user-agent', cfg['USER_AGENT'],
        '--output',     output_file,
        '--no-state',
        '--silent',
    ]

    if cfg['EXTENSIONS'].strip():
        cmd += ['--extensions', cfg['EXTENSIONS']]

    if cfg_bool(cfg, 'FOLLOW_REDIRECTS'):
        cmd.append('--redirects')

    extra = cfg.get('EXTRA_FLAGS', '').strip()
    if extra:
        cmd += extra.split()

    return cmd


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

STATUS_RE = re.compile(r'\s+(\d{3})\s+')


def check_anomaly(output_file, threshold, min_sample):
    """
    Parse feroxbuster output file for wildcard/anomaly conditions.
    Returns (anomaly_detected, pct, dominant_code) or (False, 0, None).
    """
    status_counts = defaultdict(int)
    total = 0
    try:
        with open(output_file, errors='replace') as f:
            for line in f:
                m = STATUS_RE.search(line)
                if m:
                    code = m.group(1)
                    status_counts[code] += 1
                    total += 1
    except FileNotFoundError:
        return False, 0.0, None

    if total < min_sample:
        return False, 0.0, None

    for code, count in status_counts.items():
        pct = (count / total) * 100
        if pct >= threshold:
            return True, pct, code

    return False, 0.0, None


# ---------------------------------------------------------------------------
# Job state
# ---------------------------------------------------------------------------

def make_output_filename(outdir, scheme, hostname, port):
    safe_host = re.sub(r'[^\w\-.]', '_', hostname)
    return os.path.join(outdir, f'{scheme}_{safe_host}_{port}.txt')


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def run_scheduler(resolved_urls, cfg, outdir, dry_run=False, verbose=False):
    """
    IP-aware job scheduler. Launches feroxbuster jobs ensuring only
    one job per IP runs at a time, up to MAX_JOBS concurrently.
    Monitors jobs for timeout and anomaly conditions.
    """
    max_jobs        = cfg_int(cfg, 'MAX_JOBS')
    job_timeout     = cfg_int(cfg, 'JOB_TIMEOUT')
    poll_interval   = cfg_int(cfg, 'POLL_INTERVAL')
    wc_threshold    = cfg_int(cfg, 'WILDCARD_THRESHOLD')
    wc_min_sample   = cfg_int(cfg, 'WILDCARD_MIN_SAMPLE')

    queue           = list(resolved_urls)   # (url, scheme, hostname, port, ip)
    in_flight_ips   = set()                 # IPs currently being scanned
    running_jobs    = {}                    # job_id → job dict
    job_id_counter  = 0

    summary = {
        'completed': 0,
        'timeout':   0,
        'anomaly':   0,
        'error':     0,
        'skipped':   0,
    }

    def launch_next():
        nonlocal job_id_counter
        for i, entry in enumerate(queue):
            url, scheme, hostname, port, ip = entry
            if ip not in in_flight_ips and len(running_jobs) < max_jobs:
                queue.pop(i)
                outfile = make_output_filename(outdir, scheme, hostname, port)
                cmd = build_command(url, cfg, outfile)

                if verbose or dry_run:
                    print(f'{CYAN}[>] {" ".join(cmd)}{RESET}')

                if dry_run:
                    print(f'[~] DRY RUN — skipping: {url}')
                    summary['skipped'] += 1
                    return True

                try:
                    proc = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
                except Exception as e:
                    print(f'{RED}[!] Failed to launch feroxbuster for {url}: {e}{RESET}')
                    summary['error'] += 1
                    return True

                job_id_counter += 1
                jid = job_id_counter
                running_jobs[jid] = {
                    'url':        url,
                    'scheme':     scheme,
                    'hostname':   hostname,
                    'port':       port,
                    'ip':         ip,
                    'process':    proc,
                    'start_time': time.time(),
                    'output_file':outfile,
                    'status':     'running',
                }
                in_flight_ips.add(ip)
                print(f'{GREEN}[+] Started [{jid}]: {url}  →  {ip}{RESET}')
                return True
        return False

    def check_jobs():
        finished = []
        for jid, job in running_jobs.items():
            proc      = job['process']
            elapsed   = time.time() - job['start_time']
            out_file  = job['output_file']
            url       = job['url']
            ip        = job['ip']

            # Check if process has exited
            retcode = proc.poll()

            # Timeout check
            if elapsed >= job_timeout:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                print(f'{YELLOW}[!] TIMEOUT [{jid}]: {url}  ({elapsed:.0f}s elapsed){RESET}')
                summary['timeout'] += 1
                finished.append((jid, ip, 'timeout'))
                continue

            # Anomaly check
            anomaly, pct, code = check_anomaly(out_file, wc_threshold, wc_min_sample)
            if anomaly:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                print(f'{YELLOW}[!] ANOMALY [{jid}]: {url}')
                print(f'    {pct:.1f}% of responses returned HTTP {code}')
                print(f'    Possible wildcard/tarpit. Job killed.{RESET}')
                summary['anomaly'] += 1
                finished.append((jid, ip, 'anomaly'))
                continue

            # Clean completion
            if retcode is not None:
                elapsed_str = f'{elapsed:.0f}s'
                print(f'[*] Done    [{jid}]: {url}  ({elapsed_str})')
                if retcode != 0 and verbose:
                    print(f'{YELLOW}    feroxbuster exited with code {retcode}{RESET}')
                summary['completed'] += 1
                finished.append((jid, ip, 'done'))

        for jid, ip, status in finished:
            in_flight_ips.discard(ip)
            del running_jobs[jid]

    # --- Main scheduler loop ---
    total = len(queue)
    print(f'[*] Job scheduler started. {total} URLs queued. Max {max_jobs} concurrent jobs.',
          file=sys.stderr)

    while queue or running_jobs:
        # Fill available slots
        launched = True
        while launched and (queue and len(running_jobs) < max_jobs):
            launched = launch_next()

        # Monitor running jobs
        if running_jobs:
            check_jobs()

        if queue or running_jobs:
            time.sleep(poll_interval)

    return summary


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog='veilbreak.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        description=(
            'web content enumeration at scale — powered by feroxbuster\n\n'
            'Reads HTTP/HTTPS URLs, resolves hostnames to IPs, and runs\n'
            'feroxbuster jobs concurrently with one job per IP at a time.'
        ),
        epilog=(
            'Use -hh for extended help including config reference and examples.'
        )
    )

    parser.add_argument('-h', '--help', action='store_true',
                        help='Show this help message and exit.')
    parser.add_argument('-hh', action='store_true',
                        help='Show extended help with full config reference and examples.')

    cfg_grp = parser.add_argument_group('Configuration')
    cfg_grp.add_argument('--config', default='veilbreak.conf', metavar='FILE',
                         help='Config file path. (default: veilbreak.conf)')

    input_grp = parser.add_argument_group('Input')
    input_grp.add_argument('--urls', metavar='FILE',
                           help='File of URLs to enumerate, one per line. '
                                'Reads from stdin if not specified.')

    scan_grp = parser.add_argument_group('Scan Settings (override config)')
    scan_grp.add_argument('--jobs',       metavar='N',    help='Max concurrent jobs.')
    scan_grp.add_argument('--timeout',    metavar='SEC',  help='Per-job timeout in seconds.')
    scan_grp.add_argument('--depth',      metavar='N',    help='Recursion depth.')
    scan_grp.add_argument('--threads',    metavar='N',    help='Threads per feroxbuster job.')
    scan_grp.add_argument('--wordlist',   metavar='FILE', help='Wordlist path.')
    scan_grp.add_argument('--extensions', metavar='LIST', help='Comma-separated extensions.')
    scan_grp.add_argument('--status-codes',metavar='LIST',help='Comma-separated status codes.')
    scan_grp.add_argument('--extra-flags',metavar='FLAGS',help='Extra feroxbuster flags (quoted string).')

    out_grp = parser.add_argument_group('Output')
    out_grp.add_argument('--output-dir', metavar='DIR',  help='Base output directory.')

    anom_grp = parser.add_argument_group('Anomaly Detection (override config)')
    anom_grp.add_argument('--wildcard-threshold', metavar='PCT',
                          help='Percent of same-code responses to trigger anomaly kill.')
    anom_grp.add_argument('--wildcard-min-sample', metavar='N',
                          help='Minimum responses before anomaly check activates.')

    gen_grp = parser.add_argument_group('General')
    gen_grp.add_argument('--dry-run', action='store_true',
                         help='Print feroxbuster commands without executing them.')
    gen_grp.add_argument('-v', '--verbose', action='store_true',
                         help='Show feroxbuster commands as they launch and extra status output.')

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.hh:
        print(BANNER)
        print(EXTENDED_HELP)
        sys.exit(0)

    if args.help or len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    print(BANNER)

    # --- Dependency check ---
    check_feroxbuster()

    # --- Load config and apply overrides ---
    cfg = load_config(args.config)

    if args.jobs:               cfg['MAX_JOBS']            = args.jobs
    if args.timeout:            cfg['JOB_TIMEOUT']         = args.timeout
    if args.depth:              cfg['DEPTH']               = args.depth
    if args.threads:            cfg['THREADS']             = args.threads
    if args.wordlist:           cfg['WORDLIST']            = args.wordlist
    if args.extensions:         cfg['EXTENSIONS']          = args.extensions
    if args.status_codes:       cfg['STATUS_CODES']        = args.status_codes
    if args.extra_flags:        cfg['EXTRA_FLAGS']         = args.extra_flags
    if args.output_dir:         cfg['OUTPUT_DIR']          = args.output_dir
    if args.wildcard_threshold: cfg['WILDCARD_THRESHOLD']  = args.wildcard_threshold
    if args.wildcard_min_sample:cfg['WILDCARD_MIN_SAMPLE'] = args.wildcard_min_sample

    # --- Validate wordlist ---
    if not os.path.exists(cfg['WORDLIST']):
        print(f'{RED}[!] Wordlist not found: {cfg["WORDLIST"]}{RESET}', file=sys.stderr)
        print(f'    Set WORDLIST in veilbreak.conf or use --wordlist.', file=sys.stderr)
        sys.exit(1)

    # --- Read URLs ---
    if args.urls:
        if not os.path.exists(args.urls):
            print(f'{RED}[!] URL file not found: {args.urls}{RESET}', file=sys.stderr)
            sys.exit(1)
        with open(args.urls) as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        if sys.stdin.isatty():
            print(f'{RED}[!] No URLs provided. Use --urls FILE or pipe URLs via stdin.{RESET}',
                  file=sys.stderr)
            parser.print_help()
            sys.exit(1)
        urls = [line.strip() for line in sys.stdin if line.strip()]

    if not urls:
        print(f'{RED}[!] No URLs to process.{RESET}', file=sys.stderr)
        sys.exit(1)

    # --- Create timestamped output directory ---
    run_ts  = datetime.now().strftime('%Y%m%d-%H%M%S')
    outdir  = os.path.join(cfg['OUTPUT_DIR'], run_ts)
    os.makedirs(outdir, exist_ok=True)
    print(f'[*] Output directory: {outdir}', file=sys.stderr)

    # --- Resolve hostnames ---
    resolved, failed = resolve_urls(urls, verbose=args.verbose)

    if not resolved:
        print(f'{RED}[!] No URLs could be resolved. Exiting.{RESET}', file=sys.stderr)
        sys.exit(1)

    # --- Handle Ctrl+C gracefully ---
    def sigint_handler(sig, frame):
        print(f'\n{YELLOW}[!] Interrupted. Killing running jobs...{RESET}', file=sys.stderr)
        sys.exit(1)
    signal.signal(signal.SIGINT, sigint_handler)

    # --- Run scheduler ---
    summary = run_scheduler(
        resolved, cfg, outdir,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    # --- Final summary ---
    total = len(urls)
    print(f'\n{GREEN}{BOLD}[*] veilbreak complete — run: {run_ts}{RESET}')
    print(f'    Total URLs    : {total}')
    print(f'    Completed     : {summary["completed"]}')
    print(f'    Timed out     : {summary["timeout"]}')
    print(f'    Anomaly kills : {summary["anomaly"]}')
    print(f'    Errors        : {summary["error"]}')
    print(f'    Skipped (DNS) : {len(failed)}')
    print(f'    Output dir    : {outdir}')


if __name__ == '__main__':
    main()
