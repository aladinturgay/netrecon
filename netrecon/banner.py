import socket
from dataclasses import dataclass


@dataclass(slots=True)
class BannerResult:
    port: int
    banner: str | None
    service_hint: str | None


def grab_banner(
    host: str,
    port: int,
    timeout: float,
    service_hint: str | None = None,
) -> BannerResult:
    banner: str | None = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if service_hint in {"HTTP", "HTTP-Proxy", "HTTPS", "HTTPS-Alt"}:
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                sock.sendall(probe)
            else:
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    banner = None

            if not banner:
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    banner = None
    except OSError:
        banner = None

    if banner:
        banner = " ".join(banner.split())

    return BannerResult(port=port, banner=banner or None, service_hint=service_hint)
