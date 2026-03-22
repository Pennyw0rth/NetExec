from collections import Counter
from html import escape


DEFAULT_BUILTIN_SHARE_NAMES = {"admin$", "ipc$", "print$", "netlogon", "sysvol"}


def _is_drive_admin_share(share_name: str) -> bool:
    return len(share_name) == 2 and share_name[1] == "$" and share_name[0].isalpha()


def is_default_share(share_name: str) -> bool:
    name = share_name.lower()
    return name in DEFAULT_BUILTIN_SHARE_NAMES or _is_drive_admin_share(name)


def _has_access(share: dict, permission: str) -> bool:
    return permission in {entry.upper() for entry in share.get("access", [])}


def build_report_payload(host_entries: list[dict], high_risk_names: list[str]) -> dict:
    high_risk_set = {name.lower() for name in high_risk_names}
    share_rows = []
    host_with_read = set()
    host_with_write = set()
    risky_hosts = set()
    non_default_hosts = set()
    share_name_counter = Counter()

    for host in host_entries:
        target = host.get("target", "")
        hostname = host.get("hostname", "")
        domain = host.get("domain", "")
        for share in host.get("shares", []):
            name = share.get("name", "")
            remark = share.get("remark", "")
            read_access = _has_access(share, "READ")
            write_access = _has_access(share, "WRITE")
            high_risk = name.lower() in high_risk_set
            default_share = is_default_share(name)
            access = []
            if read_access:
                access.append("READ")
            if write_access:
                access.append("WRITE")
            if not access:
                access.append("NONE")

            if read_access:
                host_with_read.add(target)
            if write_access:
                host_with_write.add(target)
            if high_risk:
                risky_hosts.add(target)
            if not default_share:
                non_default_hosts.add(target)

            share_name_counter[name.lower()] += 1
            share_rows.append(
                {
                    "target": target,
                    "hostname": hostname,
                    "domain": domain,
                    "name": name,
                    "remark": remark,
                    "access": ",".join(access),
                    "default": default_share,
                    "high_risk": high_risk,
                }
            )

    total_hosts = len({host.get("target", "") for host in host_entries if host.get("target", "")})
    total_shares = len(share_rows)
    read_shares = sum(1 for row in share_rows if "READ" in row["access"])
    write_shares = sum(1 for row in share_rows if "WRITE" in row["access"])
    non_default_shares = sum(1 for row in share_rows if not row["default"])
    high_risk_shares = sum(1 for row in share_rows if row["high_risk"])

    top_share_names = [{"name": name, "count": count} for name, count in share_name_counter.most_common(10)]

    return {
        "summary": {
            "total_hosts_scanned": total_hosts,
            "total_shares": total_shares,
            "readable_shares": read_shares,
            "writable_shares": write_shares,
            "non_default_shares": non_default_shares,
            "high_risk_shares": high_risk_shares,
            "hosts_with_read_access": len(host_with_read),
            "hosts_with_write_access": len(host_with_write),
            "hosts_with_non_default_shares": len(non_default_hosts),
            "hosts_with_high_risk_shares": len(risky_hosts),
            "high_risk_names": sorted(high_risk_set),
        },
        "top_share_names": top_share_names,
        "shares": sorted(share_rows, key=lambda row: (row["target"], row["name"])),
    }


def render_markdown_report(payload: dict) -> str:
    summary = payload["summary"]
    lines = [
        "# NetExec SMB Share Report",
        "",
        "## Summary",
        "",
        f"- Hosts scanned: {summary['total_hosts_scanned']}",
        f"- Shares discovered: {summary['total_shares']}",
        f"- Shares with READ access: {summary['readable_shares']}",
        f"- Shares with WRITE access: {summary['writable_shares']}",
        f"- Non-default shares: {summary['non_default_shares']}",
        f"- High-risk shares: {summary['high_risk_shares']}",
        f"- Hosts with readable shares: {summary['hosts_with_read_access']}",
        f"- Hosts with writable shares: {summary['hosts_with_write_access']}",
        f"- Hosts with non-default shares: {summary['hosts_with_non_default_shares']}",
        f"- Hosts with high-risk shares: {summary['hosts_with_high_risk_shares']}",
        f"- High-risk names: {', '.join(summary['high_risk_names']) if summary['high_risk_names'] else 'none'}",
        "",
        "## Top Share Names",
        "",
        "| Share Name | Count |",
        "| --- | ---: |",
    ]

    if payload["top_share_names"]:
        for item in payload["top_share_names"]:
            lines.append(f"| {item['name']} | {item['count']} |")
    else:
        lines.append("| (none) | 0 |")

    lines.extend(
        [
            "",
            "## Detailed Shares",
            "",
            "| Target | Hostname | Domain | Share | Access | Default | High Risk | Remark |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for row in payload["shares"]:
        lines.append(
            f"| {row['target']} | {row['hostname']} | {row['domain']} | {row['name']} | {row['access']} | {'yes' if row['default'] else 'no'} | {'yes' if row['high_risk'] else 'no'} | {row['remark']} |"
        )

    if not payload["shares"]:
        lines.append("| (none) |  |  |  |  |  |  |  |")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Default shares are identified using common administrative names (`ADMIN$`, `IPC$`, drive-letter admin shares like `C$`, etc.).",
            "- High-risk share names are heuristic and should be tuned for your environment.",
            "- Share access is derived from NetExec read/write checks and may differ from effective NTFS permissions.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_html_report(payload: dict) -> str:
    summary = payload["summary"]
    shares = payload["shares"]
    top_rows = []
    for item in payload["top_share_names"]:
        top_rows.append(f"<tr><td>{escape(item['name'])}</td><td>{item['count']}</td></tr>")
    if not top_rows:
        top_rows.append("<tr><td>(none)</td><td>0</td></tr>")

    host_groups = {}
    share_to_hosts = {}
    for row in shares:
        host_groups.setdefault(row["target"], []).append(row)
        share_key = row["name"].lower()
        share_entry = share_to_hosts.setdefault(
            share_key,
            {
                "name": row["name"],
                "hosts": set(),
                "instances": 0,
                "read": 0,
                "write": 0,
                "high_risk": 0,
            },
        )
        share_entry["hosts"].add(row["target"])
        share_entry["instances"] += 1
        if "READ" in row["access"]:
            share_entry["read"] += 1
        if "WRITE" in row["access"]:
            share_entry["write"] += 1
        if row["high_risk"]:
            share_entry["high_risk"] += 1

    share_pivot_rows = []
    share_host_details = []
    for key, entry in sorted(share_to_hosts.items(), key=lambda item: (-item[1]["instances"], item[0])):
        panel_id = f"share-hosts-{key.replace('$', 's').replace(' ', '-').replace('_', '-')}"
        hosts_html = "<ul>" + "".join([f"<li>{escape(host)}</li>" for host in sorted(entry["hosts"])]) + "</ul>"
        share_pivot_rows.append(
            "<tr>"
            f"<td><button class='linkbtn' type='button' onclick=\"togglePanel('{panel_id}')\">{escape(entry['name'])}</button></td>"
            f"<td>{entry['instances']}</td>"
            f"<td>{len(entry['hosts'])}</td>"
            f"<td>{entry['read']}</td>"
            f"<td>{entry['write']}</td>"
            f"<td>{entry['high_risk']}</td>"
            "</tr>"
        )
        share_host_details.append(
            f"<div id='{panel_id}' class='hidden panel'><div class='panel-title'>{escape(entry['name'])} on hosts</div>{hosts_html}</div>"
        )
    if not share_pivot_rows:
        share_pivot_rows.append("<tr><td>(none)</td><td>0</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>")

    host_sections = []
    for host in sorted(host_groups.keys()):
        host_rows = sorted(host_groups[host], key=lambda row: row["name"])
        host_rows_html = []
        for row in host_rows:
            host_rows_html.append(
                "<tr>"
                f"<td>{escape(row['name'])}</td>"
                f"<td>{escape(row['access'])}</td>"
                f"<td>{'yes' if row['default'] else 'no'}</td>"
                f"<td>{'yes' if row['high_risk'] else 'no'}</td>"
                f"<td>{escape(row['remark'])}</td>"
                "</tr>"
            )

        host_sections.append(
            "<details class='hostbox'>"
            f"<summary><strong>{escape(host)}</strong> <span class='hostmeta'>({len(host_rows)} shares)</span></summary>"
            "<table>"
            "<thead><tr><th>Share</th><th>Access</th><th>Default</th><th>High Risk</th><th>Remark</th></tr></thead>"
            "<tbody>"
            + "".join(host_rows_html)
            + "</tbody></table>"
            "</details>"
        )

    detail_host_options = ["<option value='__all__'>All Hosts</option>"]
    for host in sorted(host_groups.keys()):
        detail_host_options.append(f"<option value='{escape(host)}'>{escape(host)}</option>")

    detail_rows = []
    for row in shares:
        detail_rows.append(
            f"<tr data-host='{escape(row['target'])}'>"
            f"<td>{escape(row['target'])}</td>"
            f"<td>{escape(row['hostname'])}</td>"
            f"<td>{escape(row['domain'])}</td>"
            f"<td>{escape(row['name'])}</td>"
            f"<td>{escape(row['access'])}</td>"
            f"<td>{'yes' if row['default'] else 'no'}</td>"
            f"<td>{'yes' if row['high_risk'] else 'no'}</td>"
            f"<td>{escape(row['remark'])}</td>"
            "</tr>"
        )
    if not detail_rows:
        detail_rows.append("<tr><td colspan='8'>(none)</td></tr>")

    risk_names = ", ".join(summary["high_risk_names"]) if summary["high_risk_names"] else "none"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetExec SMB Share Report</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --card: #ffffff;
      --ink: #121826;
      --muted: #4b5563;
      --line: #d1d5db;
      --accent: #0f766e;
      --warn: #b45309;
    }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #eef2f7 0%, #f8fafc 100%);
      color: var(--ink);
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 1.25rem;
    }}
    .hero {{
      background: linear-gradient(120deg, #134e4a, #1f2937);
      color: #fff;
      border-radius: 14px;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
    }}
    .meta {{
      color: #d1d5db;
      font-size: 0.9rem;
      margin-top: 0.35rem;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1rem;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.75rem;
    }}
    .k {{
      font-size: 0.78rem;
      letter-spacing: 0.03em;
      color: var(--muted);
      text-transform: uppercase;
    }}
    .v {{
      margin-top: 0.25rem;
      font-size: 1.45rem;
      font-weight: 700;
    }}
    .section {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      margin-bottom: 1rem;
      overflow: hidden;
    }}
    .section h2 {{
      margin: 0;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--line);
      font-size: 1rem;
      background: #f8fafc;
    }}
    .section .content {{
      padding: 0.75rem 1rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.55rem;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      background: #fcfcfd;
    }}
    .foot {{
      color: var(--muted);
      font-size: 0.85rem;
      margin-top: 0.75rem;
    }}
    .hostbox {{
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-bottom: 0.65rem;
      padding: 0.5rem;
      background: #fff;
    }}
    .hostbox summary {{
      cursor: pointer;
      padding: 0.35rem 0.25rem;
      user-select: none;
    }}
    .hostmeta {{
      color: var(--muted);
      font-weight: 400;
      font-size: 0.9rem;
    }}
    .hidden {{
      display: none;
    }}
    .panel {{
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 0.6rem 0.75rem;
      margin-bottom: 0.5rem;
      background: #fff;
    }}
    .panel-title {{
      font-size: 0.9rem;
      font-weight: 600;
      margin-bottom: 0.35rem;
    }}
    .panel ul {{
      margin: 0.25rem 0 0;
      padding-left: 1.1rem;
    }}
    .linkbtn {{
      border: none;
      background: none;
      color: #0b4a6f;
      text-decoration: underline;
      cursor: pointer;
      font: inherit;
      padding: 0;
    }}
    .warn {{ color: var(--warn); font-weight: 600; }}
    .ok {{ color: var(--accent); font-weight: 600; }}
    .controls {{
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }}
    .controls label {{
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
    }}
    .controls select {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0.35rem 0.5rem;
      font: inherit;
      background: #fff;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>NetExec SMB Share Report</h1>
      <div class="meta">High-risk names: {escape(risk_names)}</div>
    </section>
    <section class="grid">
      <article class="card"><div class="k">Hosts Scanned</div><div class="v">{summary['total_hosts_scanned']}</div></article>
      <article class="card"><div class="k">Shares Found</div><div class="v">{summary['total_shares']}</div></article>
      <article class="card"><div class="k">Readable Shares</div><div class="v ok">{summary['readable_shares']}</div></article>
      <article class="card"><div class="k">Writable Shares</div><div class="v warn">{summary['writable_shares']}</div></article>
      <article class="card"><div class="k">Non-default Shares</div><div class="v">{summary['non_default_shares']}</div></article>
      <article class="card"><div class="k">High-risk Shares</div><div class="v warn">{summary['high_risk_shares']}</div></article>
    </section>
    <section class="section">
      <h2>Top Share Names</h2>
      <div class="content">
        <table>
          <thead><tr><th>Share Name</th><th>Count</th></tr></thead>
          <tbody>
            {"".join(top_rows)}
          </tbody>
        </table>
      </div>
    </section>
    <section class="section">
      <h2>Share Pivot (Click Share Name For Hosts)</h2>
      <div class="content">
        <table>
          <thead><tr><th>Share Name</th><th>Instances</th><th>Hosts</th><th>Read</th><th>Write</th><th>High Risk</th></tr></thead>
          <tbody>
            {"".join(share_pivot_rows)}
          </tbody>
        </table>
        <div style="margin-top:0.65rem;">
          {"".join(share_host_details)}
        </div>
      </div>
    </section>
    <section class="section">
      <h2>Host Breakdown</h2>
      <div class="content">
        {"".join(host_sections) if host_sections else "<p>(none)</p>"}
      </div>
    </section>
    <section class="section">
      <h2>Detailed Shares</h2>
      <div class="content">
        <div class="controls">
          <label for="detail-host-filter">Host:</label>
          <select id="detail-host-filter" onchange="filterDetailedShares()">
            {"".join(detail_host_options)}
          </select>
        </div>
        <table>
          <thead>
            <tr>
              <th>Target</th><th>Hostname</th><th>Domain</th><th>Share</th><th>Access</th><th>Default</th><th>High Risk</th><th>Remark</th>
            </tr>
          </thead>
          <tbody>
            {"".join(detail_rows)}
          </tbody>
        </table>
        <div class="foot">Access comes from NetExec SMB read/write checks and may differ from effective NTFS permissions.</div>
      </div>
    </section>
  </div>
  <script>
    function togglePanel(id) {{
      const panel = document.getElementById(id);
      if (!panel) return;
      panel.classList.toggle("hidden");
    }}
    function filterDetailedShares() {{
      const selector = document.getElementById("detail-host-filter");
      const filterValue = selector ? selector.value : "__all__";
      const tableRows = document.querySelectorAll("tr[data-host]");
      tableRows.forEach((row) => {{
        const host = row.getAttribute("data-host");
        const show = filterValue === "__all__" || host === filterValue;
        row.style.display = show ? "" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
