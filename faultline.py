#!/usr/bin/env python3
"""faultline.py — Firewall bypass detector for ICEbreaker.

Compares netsight source port scan results against baseline scans to identify
ports reachable only when traffic originates from a trusted source port.
"""

import argparse
import csv as csv_mod
import glob as glob_mod
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

RED    = '\033[91m'
BOLD   = '\033[1m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
RESET  = '\033[0m'

# ---------------------------------------------------------------------------
# Banner — computed once at import so right border is always aligned
# ---------------------------------------------------------------------------

def _make_banner():
    rows = [
        r" ____  ____  __  __  __  ____  __    ____  _  _  ____",
        r"(  __)(  _ \(  )(  )(  )(_  _)(  )  (_  _)( \( )( ___)",
        r" ) _)  )   / )(__)(  )(__ )(   )(__  _)(_  )  (  )__) ",
        r"(__)  (_)\_)(______)(____)(__)  (____)(____)(_)\_)(____)",
        r"",
        r" __/\/\___/\/\/\/\_______________/\/\____/\/\/\/\___   ",
    ]
    T     = 66          # total line width (including leading "  ")
    inner = T - 4       # width between the | chars  (T - "  |" - "|")
    sep   = "  " + "_" * (T - 2)
    lines = [sep]
    for row in rows:
        lines.append("  |" + row.ljust(inner) + "|")
    subtitle = " firewall bypass detector"
    lines.append("  |_/" + subtitle.ljust(T - 9) + r"\__|")
    return "\n" + "\n".join(lines) + "\n"


BANNER = _make_banner()


# ---------------------------------------------------------------------------
# File collection helpers
# ---------------------------------------------------------------------------

def collect_files(spec, fmt):
    """Expand a single path, comma-separated list, or glob into file paths."""
    paths = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if any(c in part for c in ('*', '?', '[')):
            matched = sorted(glob_mod.glob(part))
            if not matched:
                print(f'{YELLOW}[!] No files matched: {part}{RESET}', file=sys.stderr)
            paths.extend(matched)
        elif os.path.isfile(part):
            paths.append(part)
        else:
            print(f'{YELLOW}[!] File not found: {part}{RESET}', file=sys.stderr)
    return sorted(set(paths))


def auto_detect_baseline(outdir, fmt):
    """Return all gnmap/xml files in outdir root, excluding source-port-scan/ subdir."""
    ext    = '.xml' if fmt == 'xml' else '.gnmap'
    sp_dir = os.path.normpath(os.path.join(outdir, 'source-port-scan'))
    files  = []
    for f in sorted(glob_mod.glob(os.path.join(outdir, f'*{ext}'))):
        if os.path.normpath(f).startswith(sp_dir + os.sep):
            continue
        files.append(f)
    return files


def auto_detect_source_scans(outdir, fmt):
    """Return source port scan files from source-port-scan/ subdirectory."""
    ext    = '.xml' if fmt == 'xml' else '.gnmap'
    sp_dir = os.path.join(outdir, 'source-port-scan')
    return sorted(glob_mod.glob(os.path.join(sp_dir, f'source-*{ext}')))


def extract_source_port(filepath):
    """Pull source port number from filenames like source-53-top1k-syn.gnmap."""
    m = re.search(r'source-(\d+)-', os.path.basename(filepath))
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_gnmap(filepath):
    """Parse grepable nmap output. Returns {ip: set('port/proto')} for open ports."""
    results = defaultdict(set)
    try:
        with open(filepath) as f:
            for line in f:
                if not line.startswith('Host:'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[1]
                for m in re.finditer(r'(\d+)/open/(tcp|udp)', line):
                    results[ip].add(f'{m.group(1)}/{m.group(2)}')
    except OSError as e:
        print(f'{YELLOW}[!] Cannot read {filepath}: {e}{RESET}', file=sys.stderr)
    return dict(results)


def parse_xml(filepath):
    """Parse nmap XML output. Returns {ip: set('port/proto')} for open ports."""
    results = defaultdict(set)
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for host in root.findall('.//host'):
            addr = host.find('address[@addrtype="ipv4"]')
            if addr is None:
                addr = host.find('address[@addrtype="ipv6"]')
            if addr is None:
                continue
            ip = addr.get('addr')
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    results[ip].add(f'{port.get("portid")}/{port.get("protocol")}')
    except (ET.ParseError, OSError) as e:
        print(f'{YELLOW}[!] Cannot parse {filepath}: {e}{RESET}', file=sys.stderr)
    return dict(results)


def parse_file(filepath, fmt):
    return parse_xml(filepath) if fmt == 'xml' else parse_gnmap(filepath)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def build_baseline(files, fmt, verbose=False):
    """Merge all baseline files into {ip: set(ports)}."""
    baseline = defaultdict(set)
    for f in files:
        if verbose:
            print(f'[*] Baseline: {f}', file=sys.stderr)
        for ip, ports in parse_file(f, fmt).items():
            baseline[ip].update(ports)
    if verbose:
        total = sum(len(v) for v in baseline.values())
        print(f'[*] Baseline totals: {len(baseline)} host(s), {total} open port(s).',
              file=sys.stderr)
    return dict(baseline)


def build_source_scan_data(files, fmt, verbose=False):
    """
    Parse source port scan files.
    Returns {sport: {ip: set(ports)}} keyed by integer source port.
    """
    by_sport = defaultdict(lambda: defaultdict(set))
    for f in files:
        sport = extract_source_port(f)
        if sport is None:
            print(f'{YELLOW}[!] Cannot extract source port from filename: {f} — skipping.{RESET}',
                  file=sys.stderr)
            continue
        if verbose:
            print(f'[*] Source port {sport}: {f}', file=sys.stderr)
        for ip, ports in parse_file(f, fmt).items():
            by_sport[sport][ip].update(ports)
    return {sport: dict(hosts) for sport, hosts in by_sport.items()}


def compute_findings(baseline, by_sport):
    """
    Returns {ip: {sport: set(bypass_ports)}} — ports open only via a source port,
    not present in any baseline scan for that host.
    """
    findings = defaultdict(dict)
    for sport, scan_data in sorted(by_sport.items()):
        for ip, ports in scan_data.items():
            new_ports = ports - baseline.get(ip, set())
            if new_ports:
                findings[ip][sport] = new_ports
    return dict(findings)


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _ip_sort_key(ip):
    parts = ip.split('.')
    return [int(p) if p.isdigit() else p for p in parts]


def _port_list(ports):
    """Sort a set of 'port/proto' strings and return as a space-separated string."""
    def key(p):
        num, proto = p.split('/')
        return (proto, int(num))
    return '  '.join(sorted(ports, key=key))


def print_by_host(findings, baseline, no_color=False, outfile=None):
    """Default output: findings grouped by host."""
    if outfile is None:
        outfile = sys.stdout
    r  = RED + BOLD if not no_color else ''
    g  = GREEN      if not no_color else ''
    y  = YELLOW     if not no_color else ''
    rs = RESET      if not no_color else ''

    if not findings:
        print(f'{g}[*] No firewall bypass findings.{rs}', file=outfile)
        return

    for ip in sorted(findings, key=_ip_sort_key):
        print(f'\n{r}[!] {ip}{rs}', file=outfile)
        for sport in sorted(findings[ip]):
            ports = _port_list(findings[ip][sport])
            print(f'    source port {y}{sport:<6}{rs}  unlocks: {ports}', file=outfile)

    no_findings = len(baseline) - len(findings)
    if no_findings > 0:
        print(f'\n{g}[*] No bypass ports found on {no_findings} baseline host(s).{rs}',
              file=outfile)


def print_by_source_port(findings, no_color=False, outfile=None):
    """Output grouped by source port."""
    if outfile is None:
        outfile = sys.stdout
    r  = RED + BOLD if not no_color else ''
    g  = GREEN      if not no_color else ''
    y  = YELLOW     if not no_color else ''
    rs = RESET      if not no_color else ''

    by_sport = defaultdict(dict)
    for ip, sports in findings.items():
        for sport, ports in sports.items():
            by_sport[sport][ip] = ports

    if not by_sport:
        print(f'{g}[*] No firewall bypass findings.{rs}', file=outfile)
        return

    for sport in sorted(by_sport):
        hosts       = by_sport[sport]
        total_ports = sum(len(p) for p in hosts.values())
        print(f'\n{r}[!] Source port {sport}{rs}  '
              f'({len(hosts)} host(s), {total_ports} bypass port(s))', file=outfile)
        for ip in sorted(hosts, key=_ip_sort_key):
            print(f'    {y}{ip:<20}{rs}  {_port_list(hosts[ip])}', file=outfile)


def print_summary(findings, baseline, by_sport_data, no_color=False, outfile=None):
    """Print summary statistics block."""
    if outfile is None:
        outfile = sys.stdout
    r  = RED + BOLD if not no_color else ''
    g  = GREEN      if not no_color else ''
    y  = YELLOW     if not no_color else ''
    c  = CYAN       if not no_color else ''
    rs = RESET      if not no_color else ''

    hosts_affected = len(findings)
    total_bypasses = sum(len(p) for h in findings.values() for p in h.values())

    sport_ports  = defaultdict(int)
    sport_hosts  = defaultdict(int)
    for ip, sports in findings.items():
        for sport, ports in sports.items():
            sport_ports[sport] += len(ports)
            sport_hosts[sport] += 1

    width = 54
    print(f'\n{c}' + '─' * width + rs, file=outfile)
    print(f'{c}  SUMMARY{rs}', file=outfile)
    print(f'{c}' + '─' * width + rs, file=outfile)
    print(f'  Baseline hosts               : {len(baseline)}', file=outfile)
    print(f'  Source port profiles tested  : {len(by_sport_data)}', file=outfile)
    clr = r if hosts_affected else g
    print(f'  Hosts with bypass findings   : {clr}{hosts_affected}{rs}', file=outfile)
    clr = r if total_bypasses else g
    print(f'  Total bypass ports found     : {clr}{total_bypasses}{rs}', file=outfile)

    if sport_ports:
        best  = max(sport_ports, key=sport_ports.get)
        worst = min(sport_ports, key=sport_ports.get)
        print(f'  Most effective source port   : {y}{best}{rs}  '
              f'({sport_ports[best]} port(s) across {sport_hosts[best]} host(s))',
              file=outfile)
        if best != worst:
            print(f'  Least effective source port  : {y}{worst}{rs}  '
                  f'({sport_ports[worst]} port(s) across {sport_hosts[worst]} host(s))',
                  file=outfile)

    print(f'{c}' + '─' * width + rs, file=outfile)


def build_json(findings):
    data = {}
    for ip, sports in sorted(findings.items(), key=lambda x: _ip_sort_key(x[0])):
        data[ip] = {str(sport): sorted(ports) for sport, ports in sorted(sports.items())}
    return json.dumps(data, indent=2)


def build_csv(findings):
    buf = io.StringIO()
    writer = csv_mod.writer(buf)
    writer.writerow(['host', 'source_port', 'bypass_port', 'proto'])
    for ip in sorted(findings, key=_ip_sort_key):
        for sport in sorted(findings[ip]):
            for port_proto in sorted(findings[ip][sport]):
                port, proto = port_proto.split('/')
                writer.writerow([ip, sport, port, proto])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='faultline.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Firewall bypass detector. Compares netsight source port scan results\n'
            'against baseline scans to identify ports reachable only when traffic\n'
            'originates from a trusted source port (DNS/53, NTP/123, SNMP/161, etc.).\n\n'
            'By default reads from the current directory, expecting the netsight output\n'
            'layout: baseline gnmap files in the root, source port scans under\n'
            'source-port-scan/source-{port}-*.gnmap.'
        ),
        epilog=(
            'Source port file naming:\n'
            '  faultline reads the source port from the netsight-generated filename.\n'
            '  Expected pattern: source-{port}-top1k-{syn|udp}.gnmap\n'
            '  e.g. source-53-top1k-syn.gnmap  →  source port 53\n\n'
            'Examples:\n'
            '  # Auto-detect everything from current netsight output directory\n'
            '  python3 faultline.py\n\n'
            '  # Specific netsight output directory\n'
            '  python3 faultline.py -d ./client-results\n\n'
            '  # Override baseline files\n'
            '  python3 faultline.py -b "top10000-allup-syn.gnmap,65k-allresponding-tcp.gnmap"\n\n'
            '  # Glob input for source scans\n'
            '  python3 faultline.py -s "source-port-scan/*.gnmap"\n\n'
            '  # XML format\n'
            '  python3 faultline.py --xml -d ./results\n\n'
            '  # Group by source port\n'
            '  python3 faultline.py --by-source-port\n\n'
            '  # Summary only\n'
            '  python3 faultline.py --summary-only\n\n'
            '  # JSON export\n'
            '  python3 faultline.py --json -o findings.json\n\n'
            '  # CSV export\n'
            '  python3 faultline.py --csv -o findings.csv\n'
        ),
    )

    in_grp = parser.add_argument_group('Input')
    in_grp.add_argument(
        '-d', '--outdir', default='.', metavar='DIR',
        help='netsight output directory. Baseline and source scan files are auto-detected '
             'from this directory. (default: .)',
    )
    in_grp.add_argument(
        '-b', '--baseline', metavar='FILES',
        help='Baseline scan files. Single file, comma-separated list, or glob. '
             'Overrides auto-detection. (default: *.gnmap in --outdir, '
             'excluding source-port-scan/)',
    )
    in_grp.add_argument(
        '-s', '--source-scans', metavar='FILES',
        help='Source port scan files. Single file, comma-separated list, or glob. '
             'Overrides auto-detection. '
             '(default: source-port-scan/source-*.gnmap in --outdir)',
    )
    in_grp.add_argument(
        '--xml', action='store_true',
        help='Parse nmap XML (.xml) instead of grepable (.gnmap) format.',
    )

    out_grp = parser.add_argument_group('Output')
    mode_mx = out_grp.add_mutually_exclusive_group()
    mode_mx.add_argument(
        '--by-source-port', action='store_true',
        help='Group findings by source port rather than by host.',
    )
    mode_mx.add_argument(
        '--summary-only', action='store_true',
        help='Print only the summary statistics block.',
    )
    mode_mx.add_argument(
        '--json', action='store_true',
        help='Output findings as JSON.',
    )
    mode_mx.add_argument(
        '--csv', action='store_true',
        help='Output findings as CSV (host, source_port, bypass_port, proto).',
    )
    out_grp.add_argument(
        '-o', '--output', metavar='FILE',
        help='Write output to file instead of stdout.',
    )

    gen_grp = parser.add_argument_group('General')
    gen_grp.add_argument(
        '-v', '--verbose', action='store_true',
        help='Print file loading and parsing details to stderr.',
    )
    gen_grp.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress informational messages. Warnings and errors still appear.',
    )

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    fmt  = 'xml' if args.xml else 'gnmap'

    # --- Collect baseline files ---
    if args.baseline:
        baseline_files = collect_files(args.baseline, fmt)
    else:
        baseline_files = auto_detect_baseline(args.outdir, fmt)

    if not baseline_files:
        print(
            f'{RED}[!] No baseline scan files found. Use -b to specify files '
            f'or -d to point to a netsight output directory.{RESET}',
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Collect source port scan files ---
    if args.source_scans:
        source_files = collect_files(args.source_scans, fmt)
    else:
        source_files = auto_detect_source_scans(args.outdir, fmt)

    if not source_files:
        print(
            f'{RED}[!] No source port scan files found. Use -s to specify files '
            f'or ensure source-port-scan/ exists under --outdir.{RESET}',
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.quiet:
        print(f'[*] Baseline files   : {len(baseline_files)}', file=sys.stderr)
        print(f'[*] Source scan files: {len(source_files)}', file=sys.stderr)

    # --- Parse ---
    baseline = build_baseline(baseline_files, fmt, verbose=args.verbose)
    by_sport = build_source_scan_data(source_files, fmt, verbose=args.verbose)

    if not baseline and not args.quiet:
        print(f'{YELLOW}[!] Baseline is empty — no open ports found in baseline files.{RESET}',
              file=sys.stderr)

    # --- Compute findings ---
    findings = compute_findings(baseline, by_sport)

    if not args.quiet:
        print(
            f'[*] Baseline hosts: {len(baseline)}'
            f'  |  Source port profiles: {len(by_sport)}'
            f'  |  Hosts with findings: {len(findings)}',
            file=sys.stderr,
        )

    # --- Output ---
    no_color = bool(args.output)

    if args.output:
        outfile = open(args.output, 'w')
    else:
        outfile = sys.stdout

    try:
        if args.json:
            outfile.write(build_json(findings) + '\n')
        elif args.csv:
            outfile.write(build_csv(findings))
        elif args.summary_only:
            print_summary(findings, baseline, by_sport,
                          no_color=no_color, outfile=outfile)
        elif args.by_source_port:
            print_by_source_port(findings, no_color=no_color, outfile=outfile)
            print_summary(findings, baseline, by_sport,
                          no_color=no_color, outfile=outfile)
        else:
            print_by_host(findings, baseline, no_color=no_color, outfile=outfile)
            print_summary(findings, baseline, by_sport,
                          no_color=no_color, outfile=outfile)
    finally:
        if args.output:
            outfile.close()
            print(f'{GREEN}[*] Output written to: {args.output}{RESET}', file=sys.stderr)


if __name__ == '__main__':
    main()
