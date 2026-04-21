#!/usr/bin/env python3
"""netsight.py — Network visibility and host discovery automation for ICEbreaker."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

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
# Banners
# ---------------------------------------------------------------------------

BANNER = r"""
  0101010101010101010101010101010101010101
  1010101010101010101010101010101010101010
  0101010  ___________________________  01
  1010101 /  __                       \ 10
  0101010|  /  \   N E T S I G H T    |01
  1010101| | >> |                     |10
  0101010|  \__/  network recon       |01
  1010101 \___________________________/10
  0101010101010101010101010101010101010101
  1010101010101010101010101010101010101010
"""

WARNING_ART = r"""
  +   +  +++   +++  +  +  +++  +  +   +++
  +   + +   + +   + ++ +   +   ++ +  +
  + + + +++++ ++++  + + +   +   + + + + ++
  ++ ++ +   + +  +  +  ++   +   +  ++  +  +
  +   + +   + +   + +   + ++++  +   +  +++
"""


def warn_anomaly(reason, pct, threshold, fallback_ports):
    """Print a large red warning block to the terminal."""
    klaxon = '🚨' * 30
    print(f'\n{RED}{BOLD}')
    print(f'  {klaxon}')
    print(WARNING_ART)
    print(f'  {klaxon}')
    print()
    print(f'  !! ANOMALOUS NETWORK RESPONSE DETECTED !!')
    print()
    print(f'  Reason   : {reason}')
    print(f'  Observed : {pct:.1f}% response rate')
    print(f'  Threshold: {threshold}%')
    print()
    print(f'  This may indicate:')
    print(f'    - A honey-pot or tarpit network')
    print(f'    - A load balancer answering for all IPs')
    print(f'    - Misconfigured network infrastructure')
    print(f'    - An IDS/IPS generating synthetic responses')
    print()
    print(f'  !! NORMAL SCAN ABORTED — RUNNING FALLBACK SCAN !!')
    print(f'  !! Top {fallback_ports} ports against all targets      !!')
    print()
    print(f'  {klaxon}')
    print(f'{RESET}\n')


# ---------------------------------------------------------------------------
# Config file parser
# ---------------------------------------------------------------------------

DEFAULTS = {
    'MINRATE':               '1000',
    'MAXRTTTIMEOUT':         '200ms',
    'TOPDISCOVERYPORTS':     '1000',
    'ENUMTCPPORTS':          '10000',
    'ENUMUDPPORTS':          '10000',
    'TOPPORTSFALLBACK':      '100',
    'PING_RESPONSE_THRESHOLD': '80',
    'OPEN_PORT_THRESHOLD':   '80',
    'FULL_TCP_SCAN':         'yes',
    'FULL_UDP_SCAN':         'no',
    'EVASION_SCANS':         'yes',
    'SOURCE_PORT_SCANS':     'yes',
    'OUTPUT_DIR':            '.',
    'TARGETS_FILE':          'targets.txt',
    'EXCLUDE_FILE':          'clientexclude.txt',
}


def load_config(config_path):
    """Load a flat KEY = VALUE config file. Returns dict of settings."""
    config = dict(DEFAULTS)
    if not os.path.exists(config_path):
        print(f'{YELLOW}[!] Config file not found: {config_path} — using built-in defaults.{RESET}',
              file=sys.stderr)
        return config
    with open(config_path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                print(f'{YELLOW}[!] Skipping malformed config line {lineno}: {line}{RESET}',
                      file=sys.stderr)
                continue
            key, _, val = line.partition('=')
            config[key.strip().upper()] = val.strip()
    return config


def cfg_int(config, key):
    try:
        return int(config[key])
    except (ValueError, KeyError):
        return int(DEFAULTS[key])


def cfg_bool(config, key):
    return config.get(key, '').lower() in ('yes', 'true', '1')


# ---------------------------------------------------------------------------
# nmap runner
# ---------------------------------------------------------------------------

SOURCE_PORTS_TCP = [
    4, 6, 7, 8, 10, 12, 13, 14, 15, 16, 23, 28, 30, 32, 34, 40, 41,
    120, 122, 147, 150, 151, 153, 159, 160, 161, 167, 168, 169,
    174, 175, 176, 181, 183, 184, 185, 213, 224, 225, 226, 228,
    229, 230, 231, 233, 234, 235, 236, 237, 238, 242, 245, 248,
    249, 250, 251, 252, 253, 254, 255, 260, 262, 263, 264, 273,
    276, 277, 280, 283, 284, 287, 288, 289, 293, 294, 295, 300,
    301, 303, 305, 306, 309, 310, 312, 315, 316, 317, 321, 322,
    325, 326, 329, 334, 336, 337,
]

SOURCE_PORTS_UDP = [53, 69, 123, 137, 161, 514]


def run(cmd, dry_run=False, verbose=False):
    """Execute a shell command. Prints command if verbose or dry_run."""
    if verbose or dry_run:
        print(f'{CYAN}[>] {" ".join(cmd)}{RESET}')
    if dry_run:
        return 0
    result = subprocess.run(cmd)
    return result.returncode


def count_lines(filepath):
    """Return number of non-empty lines in a file."""
    try:
        with open(filepath) as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def extract_pingsweep_up(gnmap_file, out_file):
    """Extract IPs marked Up from a pingsweep gnmap file."""
    hosts = []
    try:
        with open(gnmap_file) as f:
            for line in f:
                if 'Status: Up' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        hosts.append(parts[1])
    except FileNotFoundError:
        pass
    with open(out_file, 'w') as f:
        for h in sorted(set(hosts)):
            f.write(h + '\n')
    return hosts


def extract_listscan_fqdns(nmap_file, out_file):
    """Extract IPs from listscan that have an FQDN (hostname in parens)."""
    import re
    hosts = []
    pattern = re.compile(r'Nmap scan report for \S+\s+\((\S+)\)')
    try:
        with open(nmap_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                m = pattern.search(line)
                if m:
                    hosts.append(m.group(1))
    except FileNotFoundError:
        pass
    with open(out_file, 'w') as f:
        for h in sorted(set(hosts)):
            f.write(h + '\n')
    return hosts


def extract_open_hosts(gnmap_file, out_file):
    """Extract IPs with any open port from a gnmap file."""
    hosts = []
    try:
        with open(gnmap_file) as f:
            for line in f:
                if 'open/' in line and line.startswith('Host:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        hosts.append(parts[1])
    except FileNotFoundError:
        pass
    hosts = sorted(set(hosts))
    with open(out_file, 'w') as f:
        for h in hosts:
            f.write(h + '\n')
    return hosts


def merge_host_files(output_file, *input_files):
    """Merge multiple host list files into one deduplicated sorted file."""
    hosts = set()
    for path in input_files:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        hosts.add(line)
        except FileNotFoundError:
            pass
    with open(output_file, 'w') as f:
        for h in sorted(hosts):
            f.write(h + '\n')
    return sorted(hosts)


def extract_open_ports(nmap_files, tcp_out, udp_out, all_out):
    """
    Extract unique open port numbers from .nmap files.
    Writes comma-separated files for TCP, UDP, and all ports.
    """
    import re
    tcp_ports, udp_ports = set(), set()
    port_re = re.compile(r'^\s*(\d+)/(tcp|udp)\s+open')
    for path in nmap_files:
        try:
            with open(path) as f:
                for line in f:
                    m = port_re.match(line)
                    if m:
                        port, proto = m.group(1), m.group(2)
                        if proto == 'tcp':
                            tcp_ports.add(port)
                        else:
                            udp_ports.add(port)
        except FileNotFoundError:
            pass

    def write_ports(ports, path):
        with open(path, 'w') as f:
            f.write(','.join(sorted(ports, key=int)) + '\n')

    write_ports(tcp_ports, tcp_out)
    write_ports(udp_ports, udp_out)
    write_ports(tcp_ports | udp_ports, all_out)


def extract_all_responding(gnmap_files, out_file, out_commas):
    """Extract all IPs with any open/tcp or open/udp port from gnmap files."""
    hosts = set()
    for path in gnmap_files:
        try:
            with open(path) as f:
                for line in f:
                    if ('open/tcp' in line or 'open/udp' in line) and line.startswith('Host:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            hosts.add(parts[1])
        except FileNotFoundError:
            pass
    hosts = sorted(hosts)
    with open(out_file, 'w') as f:
        for h in hosts:
            f.write(h + '\n')
    with open(out_commas, 'w') as f:
        f.write(','.join(hosts) + '\n')
    return hosts


def count_targets(targets_file):
    """Count number of targets in the targets file."""
    return count_lines(targets_file)


def check_ping_anomaly(pings_up_file, total_targets, threshold):
    """
    Returns (anomaly_detected, pct) based on ping sweep results.
    """
    if total_targets == 0:
        return False, 0.0
    responding = count_lines(pings_up_file)
    pct = (responding / total_targets) * 100
    return pct >= threshold, pct


def check_port_anomaly(gnmap_file, threshold):
    """
    Checks if an anomalously high percentage of host:port combos are open.
    Returns (anomaly_detected, pct).
    """
    total, open_count = 0, 0
    try:
        with open(gnmap_file) as f:
            for line in f:
                if not line.startswith('Host:'):
                    continue
                import re
                ports = re.findall(r'\d+/(\w+)/tcp', line)
                total += len(ports)
                opens = re.findall(r'\d+/open/tcp', line)
                open_count += len(opens)
    except FileNotFoundError:
        return False, 0.0
    if total == 0:
        return False, 0.0
    pct = (open_count / total) * 100
    return pct >= threshold, pct


# ---------------------------------------------------------------------------
# Phase functions
# ---------------------------------------------------------------------------

def phase_banner(msg):
    print(f'\n{GREEN}{BOLD}[*] {msg}{RESET}')


def run_fallback_scan(cfg, args, outdir, dry_run, verbose):
    """Run a conservative top-N port scan against all targets as fallback."""
    fallback_ports = cfg_int(cfg, 'TOPPORTSFALLBACK')
    minrate        = cfg['MINRATE']
    maxrtt         = cfg['MAXRTTTIMEOUT']
    targets        = cfg['TARGETS_FILE']
    exclude        = cfg['EXCLUDE_FILE']
    outbase        = os.path.join(outdir, 'fallback-scan')

    phase_banner(f'FALLBACK: Top {fallback_ports} port SYN scan against all targets')
    run([
        'sudo', 'nmap', '-n', '-Pn', '-sS',
        '--top-ports', str(fallback_ports),
        '--min-rate', minrate,
        '--max-rtt-timeout', maxrtt,
        '--max-retries', '1',
        '--excludefile', exclude,
        '-iL', targets,
        '-oA', outbase,
    ], dry_run=dry_run, verbose=verbose)


def phase1_discovery(cfg, outdir, dry_run, verbose):
    """Ping sweep + list scan host discovery."""
    minrate  = cfg['MINRATE']
    maxrtt   = cfg['MAXRTTTIMEOUT']
    targets  = cfg['TARGETS_FILE']
    exclude  = cfg['EXCLUDE_FILE']
    ping_threshold  = cfg_int(cfg, 'PING_RESPONSE_THRESHOLD')
    fallback_ports  = cfg_int(cfg, 'TOPPORTSFALLBACK')
    total_targets   = count_targets(targets)

    pingsweep_base  = os.path.join(outdir, 'pingsweep')
    pings_up        = os.path.join(outdir, 'pings-up.txt')
    excluded        = os.path.join(outdir, 'excluded.txt')
    listscan_base   = os.path.join(outdir, 'listscan')
    listscan_up     = os.path.join(outdir, 'listscan-up.txt')

    # --- Ping sweep ---
    phase_banner('Phase 1a: Ping sweep')
    run([
        'nmap', '-n', '-sn',
        '--min-rate', minrate,
        '--max-retries', '1',
        '--max-rtt-timeout', maxrtt,
        '--excludefile', exclude,
        '-iL', targets,
        '-oA', pingsweep_base,
    ], dry_run=dry_run, verbose=verbose)

    ping_hosts = extract_pingsweep_up(pingsweep_base + '.gnmap', pings_up)
    print(f'[*] Ping sweep: {len(ping_hosts)} hosts responded.', file=sys.stderr)

    # --- Honey-pot check: ping ---
    anomaly, pct = check_ping_anomaly(pings_up, total_targets, ping_threshold)
    if anomaly:
        warn_anomaly(
            'Excessive ping sweep response rate',
            pct, ping_threshold, fallback_ports
        )
        return None  # Signal fallback needed

    # Build initial excluded list
    merge_host_files(excluded, pings_up, exclude)

    # --- List scan for FQDNs ---
    phase_banner('Phase 1b: List scan (FQDN discovery)')
    run([
        'nmap', '-Pn', '-sL',
        '--excludefile', excluded,
        '-iL', targets,
        '-oA', listscan_base,
    ], dry_run=dry_run, verbose=verbose)

    fqdn_hosts = extract_listscan_fqdns(listscan_base + '.nmap', listscan_up)
    print(f'[*] List scan: {len(fqdn_hosts)} hosts with FQDNs found.', file=sys.stderr)

    # Rebuild excluded with listscan results
    merge_host_files(excluded, pings_up, listscan_up, exclude)

    return pings_up, listscan_up, excluded


def phase2_dark_ips(cfg, excluded, outdir, dry_run, verbose):
    """Dark IP discovery — SYN scan of hosts not found in phase 1."""
    minrate         = cfg['MINRATE']
    maxrtt          = cfg['MAXRTTTIMEOUT']
    targets         = cfg['TARGETS_FILE']
    discovery_ports = cfg_int(cfg, 'TOPDISCOVERYPORTS')
    port_threshold  = cfg_int(cfg, 'OPEN_PORT_THRESHOLD')
    fallback_ports  = cfg_int(cfg, 'TOPPORTSFALLBACK')

    dark_base = os.path.join(outdir, 'topports-dark-syn')
    dark_up   = os.path.join(outdir, 'dark-up.txt')

    phase_banner(f'Phase 2: Dark IP discovery (top {discovery_ports} ports)')
    run([
        'sudo', 'nmap', '-n', '-Pn', '-sS',
        '--top-ports', str(discovery_ports),
        '--min-rate', minrate,
        '--max-retries', '1',
        '--max-rtt-timeout', maxrtt,
        '--excludefile', excluded,
        '-iL', targets,
        '-oA', dark_base,
    ], dry_run=dry_run, verbose=verbose)

    dark_hosts = extract_open_hosts(dark_base + '.gnmap', dark_up)
    print(f'[*] Dark IP scan: {len(dark_hosts)} additional hosts found.', file=sys.stderr)

    # --- Honey-pot check: open ports ---
    anomaly, pct = check_port_anomaly(dark_base + '.gnmap', port_threshold)
    if anomaly:
        warn_anomaly(
            'Excessive open port response rate during dark IP scan',
            pct, port_threshold, fallback_ports
        )
        return None

    return dark_up


def phase3_enumerate(cfg, all_up, outdir, dry_run, verbose):
    """Top port enumeration of all confirmed live hosts."""
    minrate    = cfg['MINRATE']
    maxrtt     = cfg['MAXRTTTIMEOUT']
    exclude    = cfg['EXCLUDE_FILE']
    enum_tcp   = cfg_int(cfg, 'ENUMTCPPORTS')
    enum_udp   = cfg_int(cfg, 'ENUMUDPPORTS')

    tcp_base = os.path.join(outdir, f'top{enum_tcp}-allup-syn')
    udp_base = os.path.join(outdir, f'top{enum_udp}-allup-udp')

    phase_banner(f'Phase 3a: TCP enumeration (top {enum_tcp} ports)')
    run([
        'sudo', 'nmap', '-n', '-Pn', '-sS',
        '--top-ports', str(enum_tcp),
        '--min-rate', minrate,
        '--max-rtt-timeout', maxrtt,
        '--max-retries', '1',
        '--excludefile', exclude,
        '-iL', all_up,
        '-oA', tcp_base,
    ], dry_run=dry_run, verbose=verbose)

    phase_banner(f'Phase 3b: UDP enumeration (top {enum_udp} ports)')
    run([
        'sudo', 'nmap', '-n', '-Pn', '-sU',
        '--top-ports', str(enum_udp),
        '--min-rate', minrate,
        '--max-rtt-timeout', maxrtt,
        '--max-retries', '1',
        '--excludefile', exclude,
        '-iL', all_up,
        '-oA', udp_base,
    ], dry_run=dry_run, verbose=verbose)

    # Generate interim output files
    phase_banner('Phase 3c: Generating interim output files')
    nmap_files = [tcp_base + '.nmap', udp_base + '.nmap']
    extract_open_ports(
        nmap_files,
        os.path.join(outdir, 'open-ports-tcp-commas.txt'),
        os.path.join(outdir, 'open-ports-udp-commas.txt'),
        os.path.join(outdir, 'open-ports-commas.txt'),
    )
    extract_all_responding(
        [tcp_base + '.gnmap', udp_base + '.gnmap'],
        os.path.join(outdir, 'all-responding.txt'),
        os.path.join(outdir, 'all-responding-commas.txt'),
    )
    print(f'{GREEN}[*] Interim output files written. Safe to begin follow-on testing.{RESET}',
          file=sys.stderr)


def phase4_full_scan(cfg, all_up, outdir, dry_run, verbose):
    """Full 65535 port TCP and optional UDP scans."""
    minrate  = cfg['MINRATE']
    maxrtt   = cfg['MAXRTTTIMEOUT']
    exclude  = cfg['EXCLUDE_FILE']

    if cfg_bool(cfg, 'FULL_TCP_SCAN'):
        phase_banner('Phase 4a: Full 65535-port TCP scan')
        tcp_base = os.path.join(outdir, '65k-allresponding-tcp')
        run([
            'sudo', 'nmap', '-n', '-Pn', '-sS', '-p-',
            '--min-rate', minrate,
            '--max-rtt-timeout', maxrtt,
            '--max-retries', '1',
            '--excludefile', exclude,
            '-iL', all_up,
            '-oA', tcp_base,
        ], dry_run=dry_run, verbose=verbose)

    if cfg_bool(cfg, 'FULL_UDP_SCAN'):
        print(f'{YELLOW}[!] Full UDP scan enabled — this will take a very long time.{RESET}',
              file=sys.stderr)
        phase_banner('Phase 4b: Full 65535-port UDP scan')
        udp_base = os.path.join(outdir, '65k-allresponding-udp')
        run([
            'sudo', 'nmap', '-n', '-Pn', '-sU', '-p-',
            '--min-rate', minrate,
            '--max-rtt-timeout', maxrtt,
            '--max-retries', '1',
            '--excludefile', exclude,
            '-iL', all_up,
            '-oA', udp_base,
        ], dry_run=dry_run, verbose=verbose)

    # 65k output files
    gnmap_files = []
    for f in ['65k-allresponding-tcp.gnmap', '65k-allresponding-udp.gnmap']:
        p = os.path.join(outdir, f)
        if os.path.exists(p):
            gnmap_files.append(p)

    if gnmap_files:
        nmap_files = [p.replace('.gnmap', '.nmap') for p in gnmap_files]
        extract_open_ports(
            nmap_files,
            os.path.join(outdir, '65k-open-ports-tcp-commas.txt'),
            os.path.join(outdir, '65k-open-ports-udp-commas.txt'),
            os.path.join(outdir, '65k-open-ports-commas-allresponding.txt'),
        )
        extract_all_responding(
            gnmap_files,
            os.path.join(outdir, '65k-all-responding.txt'),
            os.path.join(outdir, '65k-all-responding-commas.txt'),
        )


def phase5_evasion(cfg, targets, outdir, dry_run, verbose):
    """Firewall evasion scans: XMAS, FIN, MAIMON, NULL."""
    if not cfg_bool(cfg, 'EVASION_SCANS'):
        return

    phase_banner('Phase 5: Firewall evasion scans (XMAS / FIN / MAIMON / NULL)')

    scans = [
        ('-sX', '10k-XMAS',   'XMAS'),
        ('-sF', '1k-FIN',     'FIN'),
        ('-sM', '1k-MAIMON',  'MAIMON'),
        ('-sN', '1k-NUL',     'NULL'),
    ]

    for flag, outname, label in scans:
        print(f'[*] Running {label} scan...', file=sys.stderr)
        run([
            'sudo', 'nmap', '-n', '-Pn', flag,
            '--top-ports', '1000',
            '--min-rate', '200',
            '--max-rtt-timeout', '300ms',
            '--max-retries', '1',
            '-iL', targets,
            '-oA', os.path.join(outdir, outname),
        ], dry_run=dry_run, verbose=verbose)


def phase6_source_ports(cfg, targets, outdir, dry_run, verbose):
    """Source port scans to detect firewall trust misconfigurations."""
    if not cfg_bool(cfg, 'SOURCE_PORT_SCANS'):
        return

    phase_banner('Phase 6: Source port scans')

    sp_dir = os.path.join(outdir, 'source-port-scan')
    os.makedirs(sp_dir, exist_ok=True)

    for sport in SOURCE_PORTS_TCP:
        run([
            'sudo', 'nmap', '-n', '-sS', '-Pn',
            '--top-ports', '1000',
            '-g', str(sport),
            '-iL', targets,
            '-oA', os.path.join(sp_dir, f'source-{sport}-top1k-syn'),
        ], dry_run=dry_run, verbose=verbose)

    for sport in SOURCE_PORTS_UDP:
        run([
            'sudo', 'nmap', '-n', '-sU', '-Pn',
            '--top-ports', '1000',
            '-g', str(sport),
            '-iL', targets,
            '-oA', os.path.join(sp_dir, f'source-{sport}-top1k-udp'),
        ], dry_run=dry_run, verbose=verbose)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='netsight.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Multi-phase network visibility and host discovery automation.\n'
            'Consumes a targets file, performs progressive discovery,\n'
            'detects anomalous network conditions, and enumerates live hosts.\n\n'
            'Requires nmap installed and sudo access for SYN/UDP scans.\n'
            'Place targets in targets.txt (or specify with --targets).'
        ),
        epilog=(
            'Phases:\n'
            '  1  Ping sweep + list scan (FQDN discovery)\n'
            '  2  Dark IP discovery (SYN scan of non-responding hosts)\n'
            '  3  Top port TCP/UDP enumeration of all live hosts\n'
            '  4  Full 65535-port TCP (and optional UDP) scan\n'
            '  5  Firewall evasion scans (XMAS, FIN, MAIMON, NULL)\n'
            '  6  Source port scans (firewall misconfiguration detection)\n\n'
            'Anomaly Detection:\n'
            '  If >PING_RESPONSE_THRESHOLD% of hosts respond to ping,\n'
            '  or >OPEN_PORT_THRESHOLD% of ports are open during dark IP\n'
            '  discovery, a warning is raised and a fallback scan is run\n'
            '  instead of proceeding with normal phases.\n\n'
            'Examples:\n'
            '  # Standard run with default config\n'
            '  python3 netsight.py\n\n'
            '  # Alternate config file\n'
            '  python3 netsight.py --config /path/to/custom.conf\n\n'
            '  # Override targets and output directory\n'
            '  python3 netsight.py --targets scope.txt --output-dir ./results\n\n'
            '  # Dry run: print all nmap commands without executing\n'
            '  python3 netsight.py --dry-run\n\n'
            '  # Skip slow phases\n'
            '  python3 netsight.py --no-full-tcp --no-evasion --no-source-ports\n\n'
            '  # Run fallback scan only (useful for suspected honey-pot networks)\n'
            '  python3 netsight.py --fallback-only\n\n'
            '  # Tighten anomaly detection threshold\n'
            '  python3 netsight.py --ping-threshold 60 --port-threshold 70\n\n'
            '  # Faster scan with higher min-rate\n'
            '  python3 netsight.py --minrate 2000\n\n'
            '  # Increase RTT timeout for overseas targets\n'
            '  python3 netsight.py --maxrtt 500ms\n'
        )
    )

    # --- Config ---
    cfg_grp = parser.add_argument_group(
        'Configuration',
        'Config file location and setting overrides. CLI flags take precedence over config file.'
    )
    cfg_grp.add_argument(
        '--config', default='netsight.conf', metavar='FILE',
        help='Path to configuration file. (default: netsight.conf)'
    )

    # --- Input/Output ---
    io_grp = parser.add_argument_group('Input / Output')
    io_grp.add_argument(
        '--targets', metavar='FILE',
        help='File containing target IPs, hostnames, ranges, or CIDRs. (default: targets.txt)'
    )
    io_grp.add_argument(
        '--exclude', metavar='FILE',
        help='File containing hosts/ranges to exclude. Created automatically if missing. (default: clientexclude.txt)'
    )
    io_grp.add_argument(
        '--output-dir', metavar='DIR',
        help='Directory for all scan output files. (default: .)'
    )

    # --- Scan tuning ---
    tune_grp = parser.add_argument_group(
        'Scan Tuning',
        'Override scan rate and timing settings from config.'
    )
    tune_grp.add_argument(
        '--minrate', metavar='N',
        help='Minimum nmap packet rate in packets/sec. (default: 1000)'
    )
    tune_grp.add_argument(
        '--maxrtt', metavar='TIME',
        help='Max RTT timeout (e.g. 200ms, 500ms, 1s). Double worst expected RTT. (default: 200ms)'
    )
    tune_grp.add_argument(
        '--top-discovery-ports', metavar='N', type=int,
        help='Top ports to scan during dark IP discovery phase. (default: 1000)'
    )
    tune_grp.add_argument(
        '--enum-tcp-ports', metavar='N', type=int,
        help='Top TCP ports to scan during live host enumeration. (default: 10000)'
    )
    tune_grp.add_argument(
        '--enum-udp-ports', metavar='N', type=int,
        help='Top UDP ports to scan during live host enumeration. (default: 10000)'
    )

    # --- Anomaly detection ---
    anom_grp = parser.add_argument_group(
        'Anomaly Detection',
        'Thresholds that trigger honey-pot warnings and fallback scan behavior.'
    )
    anom_grp.add_argument(
        '--ping-threshold', metavar='PCT', type=int,
        help=(
            'Percentage of hosts responding to ping sweep that triggers\n'
            'a honey-pot warning and fallback scan. (default: 80)'
        )
    )
    anom_grp.add_argument(
        '--port-threshold', metavar='PCT', type=int,
        help=(
            'Percentage of ports returning open during dark IP discovery\n'
            'that triggers a honey-pot warning and fallback scan. (default: 80)'
        )
    )
    anom_grp.add_argument(
        '--fallback-ports', metavar='N', type=int,
        help='Number of top ports to scan in fallback mode. (default: 100)'
    )

    # --- Phase toggles ---
    phase_grp = parser.add_argument_group(
        'Phase Control',
        'Enable or disable specific scan phases.'
    )
    phase_grp.add_argument(
        '--no-full-tcp', action='store_true',
        help='Skip the full 65535-port TCP scan (Phase 4).'
    )
    phase_grp.add_argument(
        '--no-full-udp', action='store_true',
        help='Skip the full 65535-port UDP scan (Phase 4). (disabled by default in config)'
    )
    phase_grp.add_argument(
        '--full-udp', action='store_true',
        help='Enable full 65535-port UDP scan even if disabled in config. Very slow.'
    )
    phase_grp.add_argument(
        '--no-evasion', action='store_true',
        help='Skip firewall evasion scans — XMAS, FIN, MAIMON, NULL (Phase 5).'
    )
    phase_grp.add_argument(
        '--no-source-ports', action='store_true',
        help='Skip source port scans (Phase 6).'
    )
    phase_grp.add_argument(
        '--fallback-only', action='store_true',
        help=(
            'Skip all normal phases and run only the fallback top-N port scan.\n'
            'Useful when you already know the network is anomalous.'
        )
    )

    # --- General ---
    gen_grp = parser.add_argument_group('General')
    gen_grp.add_argument(
        '--dry-run', action='store_true',
        help='Print all nmap commands that would be executed without running them.'
    )
    gen_grp.add_argument(
        '-v', '--verbose', action='store_true',
        help='Print each nmap command before executing it.'
    )
    gen_grp.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress phase banners. Warnings and errors still appear.'
    )

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # --- Load config then apply CLI overrides ---
    cfg = load_config(args.config)

    if args.targets:            cfg['TARGETS_FILE']           = args.targets
    if args.exclude:            cfg['EXCLUDE_FILE']            = args.exclude
    if args.output_dir:         cfg['OUTPUT_DIR']              = args.output_dir
    if args.minrate:            cfg['MINRATE']                 = args.minrate
    if args.maxrtt:             cfg['MAXRTTTIMEOUT']           = args.maxrtt
    if args.top_discovery_ports:cfg['TOPDISCOVERYPORTS']       = str(args.top_discovery_ports)
    if args.enum_tcp_ports:     cfg['ENUMTCPPORTS']            = str(args.enum_tcp_ports)
    if args.enum_udp_ports:     cfg['ENUMUDPPORTS']            = str(args.enum_udp_ports)
    if args.ping_threshold:     cfg['PING_RESPONSE_THRESHOLD'] = str(args.ping_threshold)
    if args.port_threshold:     cfg['OPEN_PORT_THRESHOLD']     = str(args.port_threshold)
    if args.fallback_ports:     cfg['TOPPORTSFALLBACK']        = str(args.fallback_ports)
    if args.no_full_tcp:        cfg['FULL_TCP_SCAN']           = 'no'
    if args.no_full_udp:        cfg['FULL_UDP_SCAN']           = 'no'
    if args.full_udp:           cfg['FULL_UDP_SCAN']           = 'yes'
    if args.no_evasion:         cfg['EVASION_SCANS']           = 'no'
    if args.no_source_ports:    cfg['SOURCE_PORT_SCANS']       = 'no'

    outdir  = cfg['OUTPUT_DIR']
    targets = cfg['TARGETS_FILE']
    exclude = cfg['EXCLUDE_FILE']

    os.makedirs(outdir, exist_ok=True)

    # Ensure exclusion file exists
    if not os.path.exists(exclude):
        print(f'[*] Creating empty exclusion file: {exclude}', file=sys.stderr)
        Path(exclude).touch()

    # Validate targets file
    if not os.path.exists(targets):
        print(f'{RED}[!] Targets file not found: {targets}{RESET}', file=sys.stderr)
        sys.exit(1)

    dry_run = args.dry_run
    verbose = args.verbose

    if dry_run:
        print(f'{YELLOW}[*] DRY RUN — no commands will be executed.{RESET}', file=sys.stderr)

    print(BANNER)

    # --- Fallback-only mode ---
    if args.fallback_only:
        print(f'{YELLOW}[!] --fallback-only specified. Skipping normal phases.{RESET}',
              file=sys.stderr)
        run_fallback_scan(cfg, args, outdir, dry_run, verbose)
        sys.exit(0)

    # --- Phase 1: Host discovery ---
    result = phase1_discovery(cfg, outdir, dry_run, verbose)
    if result is None:
        run_fallback_scan(cfg, args, outdir, dry_run, verbose)
        sys.exit(0)
    pings_up, listscan_up, excluded = result

    # --- Phase 2: Dark IPs ---
    dark_up = phase2_dark_ips(cfg, excluded, outdir, dry_run, verbose)
    if dark_up is None:
        run_fallback_scan(cfg, args, outdir, dry_run, verbose)
        sys.exit(0)

    # Build final all-up.txt
    all_up = os.path.join(outdir, 'all-up.txt')
    all_hosts = merge_host_files(all_up, pings_up, listscan_up, dark_up)
    print(f'{GREEN}[*] Total confirmed live hosts: {len(all_hosts)}{RESET}', file=sys.stderr)

    # --- Phase 3: Enumerate live hosts ---
    phase3_enumerate(cfg, all_up, outdir, dry_run, verbose)

    # --- Phase 4: Full port scans ---
    phase4_full_scan(cfg, all_up, outdir, dry_run, verbose)

    # --- Phase 5: Evasion scans ---
    phase5_evasion(cfg, targets, outdir, dry_run, verbose)

    # --- Phase 6: Source port scans ---
    phase6_source_ports(cfg, targets, outdir, dry_run, verbose)

    print(f'\n{GREEN}{BOLD}[*] netsight complete. Output in: {outdir}{RESET}\n',
          file=sys.stderr)


if __name__ == '__main__':
    main()
