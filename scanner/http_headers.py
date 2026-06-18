import requests


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def get_http_headers(domain: str) -> dict:
    result = {
        "status_code": None,
        "server": None,
        "redirects_to_https": False,
        "all_headers": {},
        "security_headers_present": [],
        "security_headers_missing": [],
        "raw_error": None,
    }

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            resp = requests.get(url, timeout=8, allow_redirects=True)
            result["status_code"] = resp.status_code
            result["server"] = resp.headers.get("Server")
            result["redirects_to_https"] = resp.url.startswith("https://")
            result["all_headers"] = dict(resp.headers)

            for h in SECURITY_HEADERS:
                if h.lower() in {k.lower() for k in resp.headers}:
                    result["security_headers_present"].append(h)
                else:
                    result["security_headers_missing"].append(h)
            break
        except requests.exceptions.SSLError:
            result["raw_error"] = "SSL error on HTTPS; tried HTTP"
            continue
        except Exception as e:
            result["raw_error"] = str(e)
            break

    return result
