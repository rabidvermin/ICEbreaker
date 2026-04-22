#!/usr/bin/env python3

import sys
import ssl
import socket
import datetime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID
    from cryptography.x509.extensions import ExtensionNotFound
except ImportError:
    print("[!] Missing dependency: pip install cryptography")
    sys.exit(1)


def parse_target(target: str) -> tuple[str, int]:
    """Parse host:port string, handling IPv6 addresses too."""
    if target.count(':') > 1:
        # Likely IPv6 — expect [::1]:443 format
        if target.startswith('['):
            host, _, port_str = target[1:].rpartition(']:')
            return host, int(port_str)
        else:
            raise ValueError("For IPv6 addresses, use bracket notation: [::1]:443")
    parts = target.rsplit(':', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid target format '{target}'. Expected <host>:<port>")
    return parts[0], int(parts[1])


def format_name(name) -> str:
    """Format an x509.Name into a readable DN string."""
    parts = []
    for attr in name:
        oid_dotted = attr.oid.dotted_string
        # Map common OIDs to short names
        short = {
            "2.5.4.3":  "CN",
            "2.5.4.6":  "C",
            "2.5.4.7":  "L",
            "2.5.4.8":  "ST",
            "2.5.4.10": "O",
            "2.5.4.11": "OU",
        }.get(oid_dotted, oid_dotted)
        parts.append(f"{short}={attr.value}")
    return ", ".join(parts) if parts else "N/A"


def get_cert_info(host: str, port: int, timeout: int = 5) -> dict:
    """Connect to host:port, perform TLS handshake, and return cert info."""
    ctx = ssl.create_default_context()
    # Allow self-signed / untrusted certs so we can still grab the data
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            der_cert = tls_sock.getpeercert(binary_form=True)
            protocol = tls_sock.version()
            cipher, _, bits = tls_sock.cipher()

    if not der_cert:
        raise ValueError("No certificate returned by server.")

    cert = x509.load_der_x509_certificate(der_cert)

    # Serial number
    serial = hex(cert.serial_number)

    # Validity
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after  = cert.not_valid_after_utc
    expires_in = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
    not_after_str = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

    # SANs
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            sans.append(f"{type(name).__name__}:{name.value}")
    except ExtensionNotFound:
        pass

    # OCSP and CA Issuers from AIA extension
    ocsp_urls = []
    ca_issuer_urls = []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access in aia.value:
            if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                ocsp_urls.append(access.access_location.value)
            elif access.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
                ca_issuer_urls.append(access.access_location.value)
    except ExtensionNotFound:
        pass

    return {
        "target":       f"{host}:{port}",
        "protocol":     protocol,
        "cipher":       cipher,
        "key_bits":     bits,
        "subject":      format_name(cert.subject),
        "issuer":       format_name(cert.issuer),
        "serial":       serial,
        "not_before":   not_before,
        "not_after":    not_after_str,
        "expires_in":   expires_in,
        "sans":         sans,
        "ocsp":         ocsp_urls,
        "ca_issuers":   ca_issuer_urls,
    }


def print_cert_info(info: dict) -> None:
    width = 60
    expired = info["expires_in"] < 0
    expiry_flag = " *** EXPIRED ***" if expired else f" (in {info['expires_in']} days)"

    print("=" * width)
    print(f"  TLS Certificate — {info['target']}")
    print("=" * width)
    print(f"  {'Protocol':<18} {info['protocol']}")
    print(f"  {'Cipher':<18} {info['cipher']} ({info['key_bits']}-bit)")
    print("-" * width)
    print(f"  {'Subject':<18} {info['subject']}")
    print(f"  {'Issuer':<18} {info['issuer']}")
    print(f"  {'Serial':<18} {info['serial']}")
    print("-" * width)
    print(f"  {'Not Before':<18} {info['not_before']}")
    print(f"  {'Not After':<18} {info['not_after']}{expiry_flag}")
    print("-" * width)
    if info["sans"]:
        print("  Subject Alt Names:")
        for san in info["sans"]:
            print(f"    • {san}")
    else:
        print("  Subject Alt Names:   (none)")
    if info["ocsp"]:
        print("  OCSP:")
        for url in info["ocsp"]:
            print(f"    • {url}")
    if info["ca_issuers"]:
        print("  CA Issuers:")
        for url in info["ca_issuers"]:
            print(f"    • {url}")
    print("=" * width)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <host>:<port>")
        print(f"  e.g. {sys.argv[0]} example.com:443")
        print(f"       {sys.argv[0]} 10.1.2.3:8443")
        sys.exit(1)

    try:
        host, port = parse_target(sys.argv[1])
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[*] Connecting to {host}:{port} ...")
    try:
        info = get_cert_info(host, port, timeout=5)
    except socket.timeout:
        print(f"[!] Connection timed out after 5 seconds.")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"[!] Connection refused on {host}:{port}")
        sys.exit(1)
    except ssl.SSLError as e:
        print(f"[!] SSL error: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Network error: {e}")
        sys.exit(1)

    print_cert_info(info)


if __name__ == "__main__":
    main()
