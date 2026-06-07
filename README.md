# 🔒 ARX IAM Safety Check

**13 security checks. One command. 10 seconds. Nothing leaves your machine.**

Not comfortable running this yourself? We'll run it for you and deliver a full report in 48 hours — [lukest@arxcloudsecurity.co.uk](mailto:lukest@arxcloudsecurity.co.uk)

A read-only Python CLI tool that scans your AWS account for critical IAM misconfigurations and identity blind spots. It runs locally using your existing credentials and produces a clean Markdown report and structured JSON output.

Most AWS startups have at least 5 misconfigurations that would fail an enterprise security questionnaire. This tool tells you exactly which ones — before a customer or auditor does.

---

## Features

- **Read-Only**: Only uses `get`, `list`, and `describe` API calls. Zero changes to your AWS environment.
- **Local Execution**: Runs entirely on your machine. No credentials or data ever leave your environment.
- **Clear Reporting**: Generates a human-readable Markdown report and a machine-readable JSON file.
- **Graceful Error Handling**: Clearly explains missing credentials or permissions without dumping Python tracebacks.

---

## What It Checks

### Core IAM (9 Checks)

| # | Check | Severity |
|---|-------|----------|
| 1 | Root Account MFA | CRITICAL |
| 2 | Root Account Access Keys | CRITICAL |
| 3 | IAM Users Without MFA | CRITICAL |
| 4 | Wildcard (`*`) IAM Policies | HIGH |
| 5 | Access Keys Older Than 90 Days | HIGH |
| 6 | Password Policy Strength | MEDIUM |
| 7 | Direct-Attached Admin Policies (not roles) | HIGH |
| 8 | CloudTrail Disabled | CRITICAL |
| 9 | Inactive IAM Users (90+ Days) | MEDIUM |

### Authority Blind Spots (4 Checks)

| # | Check | Severity |
|---|-------|----------|
| 10 | Cross-Account Trust Backdoors | HIGH |
| 11 | Publicly Exposed EBS Snapshots | CRITICAL |
| 12 | SSO / Identity Provider Integration | MEDIUM |
| 13 | Unbounded Cost-Identity Risk | MEDIUM |

---

## Quick Start

```bash
pip install -e .
arx-iam-check
```

That's it. Results appear in `./output/`:
- `report.md` — human-readable findings (share with your team)
- `results.json` — structured data (keep for your records)

---

## Prerequisites

- Python 3.9+
- AWS CLI configured (any auth method — SSO, named profile, environment variables)
- Read-only permissions (see below)

---

## What Permissions Does It Need?

Minimal. The tool is **read-only** — it checks your configuration, it doesn't change anything.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListMFADevices",
                "iam:ListPolicies",
                "iam:GetPolicyVersion",
                "iam:ListAccessKeys",
                "iam:GetAccountPasswordPolicy",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:GetUserPolicy",
                "iam:GetAccessKeyLastUsed",
                "iam:ListSAMLProviders",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "ec2:DescribeSnapshots",
                "sts:GetCallerIdentity",
                "sso-admin:ListInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Who This Is For

- Startup CTOs preparing for their first enterprise customer
- Engineering leads who know security is a gap but haven't addressed it
- Founders approaching SOC 2 / Cyber Essentials and want a quick baseline

---

## What This Doesn't Cover

IAM and identity are one layer. Your S3 bucket policies, networking, encryption, secrets management, and 30+ other categories aren't assessed here.

**Want the full picture?** ARX Cloud Security runs a comprehensive diagnostic across 8 security domains — prioritised findings and a remediation roadmap delivered in 5 days.

→ lukest@arxcloudsecurity.co.uk

---

## Troubleshooting

**Error: `Unable to locate credentials`**

Your AWS CLI isn't configured or the profile isn't active. Fix:
```bash
# Option 1 — run with a named profile
AWS_PROFILE=your-profile-name arx-iam-check

# Option 2 — configure the default profile
aws configure
```
Then run `aws sts get-caller-identity` to confirm credentials are working before running the tool.

---

**Error: `ModuleNotFoundError: No module named 'boto3'`**

boto3 isn't installed in your current environment. Fix:
```bash
# If you installed with pip install -e .
pip install boto3

# If you're using a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows
pip install -e .
arx-iam-check
```

---

**Error: `AccessDenied` on one or more checks**

Your IAM user or role is missing one of the required read permissions. The tool will still run and report results for the checks it can complete — the denied check will show as `SKIPPED` with the specific permission flagged.

To fix, attach the permissions policy from the **What Permissions Does It Need?** section above to your IAM user or role.

---

**Tool runs but output folder is empty**

The `output/` folder is created in the directory where you run the command. Make sure you're running from inside the cloned repo:
```bash
cd arx-iam-check
arx-iam-check
```

---

**Still stuck?** Open an issue at [github.com/arx-cloud-security/arx-iam-check/issues](https://github.com/arx-cloud-security/arx-iam-check/issues) or email lukest@arxcloudsecurity.co.uk

---

## License

MIT — use it, fork it, run it on everything.

---

Built by [ARX Cloud Security](https://arxcloudsecurity.co.uk) 🇬🇧
