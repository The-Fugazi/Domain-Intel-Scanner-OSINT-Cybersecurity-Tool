import dns.resolver


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def get_dns(domain: str) -> dict:
    result = {}

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            result[rtype] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            result[rtype] = []
        except dns.resolver.NXDOMAIN:
            result[rtype] = "NXDOMAIN"
        except Exception as e:
            result[rtype] = f"error: {str(e)}"

    return result
