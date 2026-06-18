import socket


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def scan_ports(domain: str) -> dict:
    result = {"open": [], "closed": [], "target_ip": None}

    try:
        ip = socket.gethostbyname(domain)
        result["target_ip"] = ip
    except Exception as e:
        result["error"] = str(e)
        return result

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            conn = sock.connect_ex((ip, port))
            if conn == 0:
                result["open"].append({"port": port, "service": service})
            else:
                result["closed"].append(port)
            sock.close()
        except Exception:
            result["closed"].append(port)

    return result
