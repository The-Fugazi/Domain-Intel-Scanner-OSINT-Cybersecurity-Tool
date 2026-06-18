import json
import os
from datetime import datetime

from scanner.http_headers import SECURITY_HEADERS


def print_summary(report: dict):
    meta = report["meta"]
    risk = report["risk_assessment"]
    whois = report["whois"]
    headers = report["http_headers"]
    ports = report["port_scan"]

    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    color = (
        RED if risk["rating"] == "HIGH"
        else YELLOW if risk["rating"] == "MEDIUM"
        else GREEN
    )

    print("\n" + "=" * 60)
    print(f"{BOLD}  DOMAIN INTELLIGENCE REPORT{RESET}")
    print("=" * 60)
    print(f"  Target     : {meta['target']}")
    print(f"  Scanned    : {meta['scanned_at']}")
    print(f"  Registrar  : {whois.get('registrar') or 'Unknown'}")
    print(f"  Domain Age : {whois.get('domain_age_days', 'Unknown')} days")
    print(f"  Created    : {whois.get('creation_date') or 'Unknown'}")
    print(f"  Expires    : {whois.get('expiration_date') or 'Unknown'}")
    print(f"  Server     : {headers.get('server') or 'Not disclosed'}")
    print(f"  HTTPS      : {'Yes' if headers.get('redirects_to_https') else 'No'}")

    open_ports = ports.get("open", [])
    port_str = (
        ", ".join(f"{p['port']} ({p['service']})" for p in open_ports)
        if open_ports else "None detected"
    )
    print(f"  Open Ports : {port_str}")

    missing = headers.get("security_headers_missing", [])
    print(f"\n  Security Headers Missing : {len(missing)}/{len(SECURITY_HEADERS)}")
    for h in missing:
        print(f"    - {h}")

    print(f"\n{BOLD}  RISK SCORE : {color}{risk['score']} / 100 — {risk['rating']}{RESET}")
    if risk["flags"]:
        print(f"\n  Risk Flags:")
        for f in risk["flags"]:
            print(f"    ! {f}")

    print("=" * 60 + "\n")


def save_report(report: dict, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    domain_slug = report["meta"]["target"].replace(".", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/{domain_slug}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  [+] JSON report saved to: {filename}")
    return filename
