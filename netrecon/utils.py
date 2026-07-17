import ipaddress
import socket
from typing import Iterable


COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 27017,
)

SERVICE_HINTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def resolve_target(target: str) -> str:
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc


def parse_ports(port_spec: str | None) -> list[int]:
    if not port_spec:
        return list(COMMON_PORTS)

    ports: set[int] = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    if not ports:
        raise ValueError("No valid ports were provided.")

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"Invalid port numbers: {sorted(invalid)}")

    return sorted(ports)


def chunked(items: Iterable[int], size: int) -> Iterable[list[int]]:
    batch: list[int] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
