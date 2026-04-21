#!/usr/bin/env python3
"""Analyze grepable nmap output and report port frequency sorted by occurrence count."""

import argparse
import glob
import re
import sys
from collections import Counter

BANNER = r"""
  +++++  ++++   +++++   +++   +   +  +++++  ++++
  +      +   +  +      +   +  +   +  +      +   +
  ++++   ++++   +++    + + +  +   +  +++    ++++
  +      + +    +      + ++   +   +  +      + +
  +      +  ++  +++++   +++    +++   +++++  +  ++

        port frequency analyzer :: grepable nmap

     /\      /\      /\      /\      /\      /\
    /  \    /  \    /  \    /  \    /  \    /  \
   /    \  /    \  /    \  /    \  /    \  /    \
--/------\/------\/------\/------\/------\/------\-- 0Hz
  \      /\      /\      /\      /\      /\      /
   \    /  \    /  \    /  \    /  \    /  \    /
    \  /    \  /    \  /    \  /    \  /    \  /
     \/      \/      \/      \/      \/      \/
"""


def parse_gnmap(filepath):
    port_counter = Counter()
    port_re = re.compile(r'(\d+)/open/')

    with open(filepath, 'r') as f:
        for line in f:
            if not line.startswith('Host:'):
                continue
            for port in port_re.findall(line):
                port_counter[int(port)] += 1

    return port_counter


def resolve_files(file_args):
    """Expand comma-separated lists and glob patterns into a deduplicated file list."""
    resolved = []
    for arg in file_args:
        for entry in arg.split(','):
            entry = entry.strip()
            if not entry:
                continue
            matches = glob.glob(entry)
            if matches:
                resolved.extend(matches)
            else:
                # Pass through as-is; open() will raise a useful error
                resolved.append(entry)
    # Deduplicate while preserving order
    seen = set()
    return [f for f in resolved if not (f in seen or seen.add(f))]


def main():
    parser = argparse.ArgumentParser(description='Analyze grepable nmap output for port frequency.')
    parser.add_argument('files', nargs='+', metavar='FILE',
                        help='One or more .gnmap files. Accepts space-separated, '
                             'comma-separated, or glob patterns (e.g. "tcp*.gnmap")')
    parser.add_argument('-l', '--list', action='store_true',
                        help='Output ports ordered by frequency on a single line, no counts')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Write output to FILE instead of stdout')

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    file_list = resolve_files(args.files)

    if not file_list:
        print("No files matched.", file=sys.stderr)
        sys.exit(1)

    total_counts = Counter()
    for filepath in file_list:
        try:
            total_counts += parse_gnmap(filepath)
            print(f"Loaded: {filepath}", file=sys.stderr)
        except FileNotFoundError:
            print(f"Warning: file not found: {filepath}", file=sys.stderr)
        except PermissionError:
            print(f"Warning: permission denied: {filepath}", file=sys.stderr)

    if not total_counts:
        print("No open ports found.", file=sys.stderr)
        sys.exit(0)

    sorted_ports = sorted(total_counts.items(), key=lambda x: (-x[1], x[0]))

    if args.list:
        output = ','.join(str(port) for port, _ in sorted_ports)
    else:
        output = '\n'.join(f"{port:<10}{count}" for port, count in sorted_ports)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output + '\n')
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
