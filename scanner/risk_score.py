from scanner.http_headers import SECURITY_HEADERS


def calculate_risk(whois_data: dict, header_data: dict, port_data: dict) -> dict:
    score = 0
    flags = []

    # Domain age
    age = whois_data.get("domain_age_days")
    if age is None:
        score += 25
        flags.append("WHOIS hidden or failed — domain age unknown (+25)")
    elif age < 180:
        score += 20
        flags.append(f"Domain is very young ({age} days old) (+20)")
    elif age < 365:
        score += 10
        flags.append(f"Domain is less than 1 year old ({age} days) (+10)")

    # Registrar anomaly
    registrar = whois_data.get("registrar") or ""
    suspicious_registrars = ["namecheap", "godaddy proxy", "privacyguardian", "whoisguard"]
    if any(s in registrar.lower() for s in suspicious_registrars):
        score += 10
        flags.append(f"Privacy-shielded or suspicious registrar: {registrar} (+10)")

    # Security headers
    missing = header_data.get("security_headers_missing", [])
    if len(missing) >= 5:
        score += 20
        flags.append(f"Missing {len(missing)} security headers (+20)")
    elif len(missing) >= 3:
        score += 10
        flags.append(f"Missing {len(missing)} security headers (+10)")

    # HTTPS
    if not header_data.get("redirects_to_https"):
        score += 15
        flags.append("No HTTPS redirect (+15)")

    # Risky open ports
    open_ports = [p["port"] for p in port_data.get("open", [])]
    risky = [p for p in open_ports if p in [21, 23, 3389, 5900]]
    if risky:
        score += 15
        flags.append(f"Risky ports open: {risky} (+15)")

    # Telnet specifically
    if 23 in open_ports:
        score += 10
        flags.append("Telnet port open — significant risk (+10)")

    # Rating
    if score >= 60:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return {"score": score, "rating": rating, "flags": flags}
