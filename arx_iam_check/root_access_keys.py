def run_check(iam_client, cloudtrail_client):
    summary = iam_client.get_account_summary()
    keys_present = summary.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0) > 0
    
    return {
        "id": "ROOT_ACCESS_KEYS",
        "title": "Root Account Access Keys",
        "severity": "CRITICAL",
        "status": "PASS" if not keys_present else "FAIL",
        "detail": "No access keys exist for the root account" if not keys_present else "Root account has active access keys",
        "why_it_matters": "Root access keys provide full, permanent access and cannot be restricted by IAM policies. Use IAM users or roles instead."
    }
