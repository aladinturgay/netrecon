import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from netrecon.banner import BannerResult, grab_banner
from netrecon.utils import SERVICE_HINTS


@dataclass(slots=True)
class ScanResult:
    host: str
    resolved_ip: str
    open_ports: list[int] = field(default_factory=list)
    banners: list[BannerResult] = field(default_factory=list)


def _probe_port(host: str, port: int, timeout: float) -> int | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            return port
    return None


def scan_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float = 0.35,
    workers: int = 100,
    grab_banners: bool = True,
) -> ScanResult:
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_probe_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort()
    banners: list[BannerResult] = []

    if grab_banners and open_ports:
        with ThreadPoolExecutor(max_workers=min(workers, len(open_ports))) as executor:
            futures = {
                executor.submit(
                    grab_banner,
                    host,
                    port,
                    timeout,
                    SERVICE_HINTS.get(port),
                ): port
                for port in open_ports
            }
            for future in as_completed(futures):
                banners.append(future.result())

        banners.sort(key=lambda item: item.port)

    return ScanResult(
        host=host,
        resolved_ip=host,
        open_ports=open_ports,
        banners=banners,
    )
