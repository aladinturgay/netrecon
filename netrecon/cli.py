import argparse
import sys
from pathlib import Path

from netrecon import __version__
from netrecon.report import format_text_report, write_html_report, write_json_report
from netrecon.scanner import scan_ports
from netrecon.utils import parse_ports, resolve_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description=(
            "TCP port tarayici. Sadece izinli sistemlerde kullan."
        ),
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p",
        "--ports",
        help="Ports to scan (example: 22,80,443 or 1-1024). Defaults to common ports.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.35,
        help="Socket timeout in seconds (default: 0.35)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Maximum worker threads (default: 100)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing on open ports",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional JSON report output path",
    )
    parser.add_argument(
        "--html",
        type=Path,
        help="Optional HTML audit report output path",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"NetRecon {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        resolved_ip = resolve_target(args.target)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    print(f"[*] Target: {args.target} ({resolved_ip})")
    print(f"[*] Scanning {len(ports)} port(s)...")

    result = scan_ports(
        resolved_ip,
        ports,
        timeout=args.timeout,
        workers=max(1, args.workers),
        grab_banners=not args.no_banner,
    )
    result.host = args.target

    report = format_text_report(result)
    print()
    print(report)

    if args.output:
        write_json_report(result, args.output)
        print(f"\n[+] JSON report saved to: {args.output}")

    if args.html:
        write_html_report(result, args.html)
        print(f"[+] HTML report saved to: {args.html}")

    return 0 if result.open_ports else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
