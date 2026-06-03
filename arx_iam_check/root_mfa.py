def run_check(iam_client, cloudtrail_client):
    summary = iam_client.get_account_summary()
    mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 1
    
    return {
        "id": "ROOT_MFA",
        "title": "Root Account MFA",
        "severity": "CRITICAL",
        "status": "PASS" if mfa_enabled else "FAIL",
        "detail": "Root account MFA is enabled" if mfa_enabled else "Root account MFA is not enabled",
        "why_it_matters": "If compromised, attacker has unrestricted access to your entire AWS account"
    }
