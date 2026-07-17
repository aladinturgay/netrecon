import json
from datetime import datetime, timezone
from pathlib import Path

from netrecon.scanner import ScanResult
from netrecon.utils import SERVICE_HINTS


def format_text_report(result: ScanResult) -> str:
    lines = [
        "NetRecon Scan Report",
        "====================",
        f"Target      : {result.host}",
        f"Resolved IP : {result.resolved_ip}",
        f"Open ports  : {len(result.open_ports)}",
        "",
    ]

    if not result.open_ports:
        lines.append("No open ports detected in the selected range.")
        return "\n".join(lines)

    banner_map = {item.port: item for item in result.banners}

    lines.append(f"{'PORT':<8}{'SERVICE':<14}{'BANNER'}")
    lines.append("-" * 72)

    for port in result.open_ports:
        service = SERVICE_HINTS.get(port, "unknown")
        banner = banner_map.get(port)
        banner_text = banner.banner if banner and banner.banner else "-"
        lines.append(f"{port:<8}{service:<14}{banner_text}")

    return "\n".join(lines)


def write_json_report(result: ScanResult, output_path: Path) -> None:
    payload = {
        "tool": "NetRecon",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.host,
        "resolved_ip": result.resolved_ip,
        "open_ports": result.open_ports,
        "services": [
            {
                "port": port,
                "service": SERVICE_HINTS.get(port, "unknown"),
                "banner": next(
                    (item.banner for item in result.banners if item.port == port),
                    None,
                ),
            }
            for port in result.open_ports
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html_report(result: ScanResult, output_path: Path) -> None:
    banner_map = {item.port: item for item in result.banners}
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for port in result.open_ports:
        service = SERVICE_HINTS.get(port, "unknown")
        banner = banner_map.get(port)
        banner_text = banner.banner if banner and banner.banner else "-"
        rows.append(
            f"<tr><td>{port}</td><td>{service}</td><td>{_escape(banner_text)}</td></tr>"
        )

    table_body = "\n".join(rows) if rows else (
        "<tr><td colspan='3'>No open ports detected.</td></tr>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetRecon Report - {_escape(result.host)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
    .card {{ max-width: 960px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }}
    h1 {{ margin-top: 0; color: #38bdf8; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 20px 0; }}
    .meta div {{ background: #334155; padding: 12px; border-radius: 8px; }}
    .meta strong {{ display: block; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #475569; text-align: left; vertical-align: top; }}
    th {{ color: #38bdf8; }}
    footer {{ margin-top: 20px; color: #94a3b8; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>NetRecon Scan Report</h1>
    <div class="meta">
      <div><strong>Target</strong>{_escape(result.host)}</div>
      <div><strong>Resolved IP</strong>{_escape(result.resolved_ip)}</div>
      <div><strong>Open Ports</strong>{len(result.open_ports)}</div>
      <div><strong>Generated</strong>{generated_at}</div>
    </div>
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
      <tbody>
        {table_body}
      </tbody>
    </table>
    <footer>Educational use only. Authorized testing environments only.</footer>
  </div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
