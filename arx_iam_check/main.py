import sys
import os
import boto3
import botocore.exceptions

from arx_iam_check import (
    root_mfa,
    root_access_keys,
    user_mfa,
    wildcard_policies,
    access_key_age,
    password_policy,
    admin_attached,
    cloudtrail,
    inactive_users,
    sso_idp,
    cross_account,
    exposed_snapshots,
    cost_explosion,
)
from arx_iam_check.report import markdown, json_out
from arx_iam_check import errors

VERSION = "1.1.0"

CHECKS = [
    root_mfa,
    root_access_keys,
    user_mfa,
    wildcard_policies,
    access_key_age,
    password_policy,
    admin_attached,
    cloudtrail,
    inactive_users,
    cross_account,
    exposed_snapshots,
    sso_idp,
    cost_explosion,
]

def main():
    print(f"🔒 ARX IAM Safety Check v{VERSION}")
    print("   Running 13 checks against your AWS account...\n")

    try:
        session = boto3.Session(region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        iam_client = session.client("iam")
        cloudtrail_client = session.client("cloudtrail")
        sts_client = session.client("sts")
        account_id = sts_client.get_caller_identity()["Account"]
    except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as e:
        errors.handle(e)
        sys.exit(1)

    findings = []
    for check in CHECKS:
        try:
            result = check.run_check(iam_client, cloudtrail_client)
            findings.append(result)
            icon = "✅" if result["status"] == "PASS" else ("ℹ️ " if result["status"] in ("INFO", "ERROR") else "❌")
            print(f"  {icon} [{result['severity']:8}] {result['title']}")
        except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as e:
            errors.handle(e)
            sys.exit(1)

    print()

    os.makedirs("output", exist_ok=True)
    markdown.write(findings, account_id, "output/report.md")
    json_out.write(findings, account_id, "output/results.json")

    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    pass_count = sum(1 for f in findings if f["status"] == "PASS")
    skip_count = sum(1 for f in findings if f["status"] in ("INFO", "ERROR"))

    print(f"  Results: {fail_count} failed · {pass_count} passed · {skip_count} skipped")
    print()
    print("  📄 output/report.md")
    print("  📊 output/results.json")
    print()

if __name__ == "__main__":
    main()
