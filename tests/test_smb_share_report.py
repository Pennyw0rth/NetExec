from nxc.protocols.smb.share_report import build_report_payload, render_markdown_report, render_html_report


def test_build_report_payload_summary_counts():
    host_entries = [
        {
            "target": "10.10.10.10",
            "hostname": "fs01",
            "domain": "corp.local",
            "shares": [
                {"name": "ADMIN$", "remark": "Remote Admin", "access": ["READ"]},
                {"name": "Finance", "remark": "Finance data", "access": ["READ", "WRITE"]},
            ],
        },
        {
            "target": "10.10.10.11",
            "hostname": "ws01",
            "domain": "corp.local",
            "shares": [
                {"name": "IPC$", "remark": "IPC", "access": []},
            ],
        },
    ]

    payload = build_report_payload(host_entries, ["admin$", "wwwroot"])
    summary = payload["summary"]

    assert summary["total_hosts_scanned"] == 2
    assert summary["total_shares"] == 3
    assert summary["readable_shares"] == 2
    assert summary["writable_shares"] == 1
    assert summary["non_default_shares"] == 1
    assert summary["high_risk_shares"] == 1
    assert summary["hosts_with_read_access"] == 1
    assert summary["hosts_with_write_access"] == 1
    assert summary["hosts_with_non_default_shares"] == 1
    assert summary["hosts_with_high_risk_shares"] == 1


def test_render_markdown_report_contains_sections():
    payload = build_report_payload(
        [
            {
                "target": "10.10.10.10",
                "hostname": "fs01",
                "domain": "corp.local",
                "shares": [{"name": "Finance", "remark": "Finance data", "access": ["READ"]}],
            }
        ],
        ["admin$"],
    )
    markdown = render_markdown_report(payload)

    assert "# NetExec SMB Share Report" in markdown
    assert "## Summary" in markdown
    assert "## Top Share Names" in markdown
    assert "## Detailed Shares" in markdown
    assert "Finance" in markdown


def test_render_html_report_contains_sections():
    payload = build_report_payload(
        [
            {
                "target": "10.10.10.10",
                "hostname": "fs01",
                "domain": "corp.local",
                "shares": [{"name": "Finance", "remark": "Finance data", "access": ["READ"]}],
            }
        ],
        ["admin$"],
    )
    html = render_html_report(payload)

    assert "<!doctype html>" in html.lower()
    assert "NetExec SMB Share Report" in html
    assert "Top Share Names" in html
    assert "Share Pivot (Click Share Name For Hosts)" in html
    assert "Host Breakdown" in html
    assert "Detailed Shares" in html
    assert "Finance" in html
