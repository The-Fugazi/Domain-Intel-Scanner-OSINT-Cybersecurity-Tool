"""
Domain Intelligence Scanner
Usage: python main.py <domain>
Example: python main.py google.com
"""

import sys
from datetime import datetime, timezone

from scanner.whois_lookup import get_whois
from scanner.dns_lookup import get_dns
from scanner.http_headers import get_http_headers
from scanner.port_scan import scan_ports
from scanner.risk_score import calculate_risk
from scanner.report import print_summary, save_report


def build_report(domain: str) -> dict:
    print(f"\n[*] Scanning: {domain}")
    print("    -> WHOIS lookup...")
    whois_data = get_whois(domain)

    print("    -> DNS records...")
    dns_data = get_dns(domain)

    print("    -> HTTP headers...")
    header_data = get_http_headers(domain)

    print("    -> Port scan...")
    port_data = scan_ports(domain)

    print("    -> Calculating risk score...")
    risk = calculate_risk(whois_data, header_data, port_data)

    return {
        "meta": {
            "target": domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "tool": "Domain Intelligence Scanner v1.0",
        },
        "whois": whois_data,
        "dns": dns_data,
        "http_headers": header_data,
        "port_scan": port_data,
        "risk_assessment": risk,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        print("Example: python main.py google.com")
        sys.exit(1)

    domain = (
        sys.argv[1]
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    report = build_report(domain)
    print_summary(report)
    save_report(report)
