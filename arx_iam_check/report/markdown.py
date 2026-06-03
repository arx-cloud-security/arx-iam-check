import os
from datetime import datetime, timezone

def _mask_account_id(account_id):
    if account_id and len(account_id) >= 4:
        return "*" * (len(account_id) - 4) + account_id[-4:]
    return "****"

def write(findings, account_id, output_path="output/report.md"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    critical = [f for f in findings if f["status"] == "FAIL" and f["severity"] == "CRITICAL"]
    high     = [f for f in findings if f["status"] == "FAIL" and f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["status"] == "FAIL" and f["severity"] == "MEDIUM"]
    passed   = [f for f in findings if f["status"] == "PASS"]
    skipped  = [f for f in findings if f["status"] in ("ERROR", "INFO")]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    masked = _mask_account_id(account_id)

    lines = [
        "# 🔒 ARX IAM Safety Check — Report",
        "",
        f"**Account:** `{masked}`  ",
        f"**Generated:** {now}  ",
        f"**Total checks:** {len(findings)}  ",
        "",
        "---",
        "",
    ]

    if critical:
        lines.append("## 🔴 Critical")
        lines.append("")
        for f in critical:
            lines += _finding_block(f)

    if high:
        lines.append("## 🟠 High")
        lines.append("")
        for f in high:
            lines += _finding_block(f)

    if medium:
        lines.append("## 🟡 Warning")
        lines.append("")
        for f in medium:
            lines += _finding_block(f)

    if passed:
        lines.append("## ✅ Passed")
        lines.append("")
        for f in passed:
            lines.append(f"- **{f['title']}** — {f['detail']}")
        lines.append("")

    if skipped:
        lines.append("## ℹ️ Skipped")
        lines.append("")
        for f in skipped:
            lines.append(f"- **{f['title']}** — {f['detail']}")
        lines.append("")

    lines += [
        "---",
        "",
        "## What's Not Covered",
        "",
        "This assessed IAM and identity configuration only. Your S3 buckets, networking, encryption, logging, and 30+ other categories were not checked.",
        "",
        "**Want the full picture?** → hello@arx-cloud.security",
        "",
    ]

    with open(output_path, "w") as fh:
        fh.write("\n".join(lines))

def _finding_block(f):
    return [
        f"### {f['title']}",
        "",
        f"**Status:** {f['status']}  ",
        f"**Severity:** {f['severity']}  ",
        "",
        f"{f['detail']}",
        "",
        f"> 💡 {f['why_it_matters']}",
        "",
        "---",
        "",
    ]
