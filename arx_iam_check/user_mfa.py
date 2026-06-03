def run_check(iam_client, cloudtrail_client):
    users = iam_client.list_users()["Users"]
    users_without_mfa = []
    
    for user in users:
        username = user["UserName"]
        mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            users_without_mfa.append(username)
            
    status = "PASS" if not users_without_mfa else "FAIL"
    detail = "All IAM users have MFA enabled" if status == "PASS" else f"{len(users_without_mfa)} users do not have MFA enabled: {', '.join(users_without_mfa[:5])}{'...' if len(users_without_mfa) > 5 else ''}"
    
    return {
        "id": "USER_MFA",
        "title": "IAM Users Without MFA",
        "severity": "CRITICAL",
        "status": status,
        "detail": detail,
        "why_it_matters": "MFA is the single most effective control to prevent unauthorized access from stolen credentials."
    }
