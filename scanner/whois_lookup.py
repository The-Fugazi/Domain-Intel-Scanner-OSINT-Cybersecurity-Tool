import whois
from datetime import datetime, timezone


def get_whois(domain: str) -> dict:
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "raw_error": None,
    }
    try:
        w = whois.whois(domain)

        result["registrar"] = w.registrar

        def extract_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
            return None

        creation = extract_date(w.creation_date)
        expiration = extract_date(w.expiration_date)
        updated = extract_date(w.updated_date)

        result["creation_date"] = creation.isoformat() if creation else None
        result["expiration_date"] = expiration.isoformat() if expiration else None
        result["updated_date"] = updated.isoformat() if updated else None

        if creation:
            age = (datetime.now(timezone.utc) - creation).days
            result["domain_age_days"] = age

        result["name_servers"] = (
            [str(ns).lower() for ns in w.name_servers]
            if isinstance(w.name_servers, list)
            else ([str(w.name_servers).lower()] if w.name_servers else [])
        )
        result["status"] = (
            w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        )
        result["emails"] = (
            w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
        )
    except Exception as e:
        result["raw_error"] = str(e)

    return result
