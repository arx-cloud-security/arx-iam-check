import botocore.exceptions

def run_check(iam_client, cloudtrail_client):
    try:
        policy = iam_client.get_account_password_policy()["PasswordPolicy"]
        
        checks = [
            policy.get("MinimumPasswordLength", 0) >= 14,
            policy.get("RequireSymbols", False),
            policy.get("RequireNumbers", False),
            policy.get("RequireUppercase", False),
            policy.get("RequireLowercase", False)
        ]
        
        is_strong = all(checks)
        detail = "Password policy meets security requirements" if is_strong else "Password policy is too weak (requires 14+ chars, symbols, numbers, upper/lower case)"
        status = "PASS" if is_strong else "FAIL"
        
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
            status = "FAIL"
            detail = "No custom password policy is defined for this account"
        else:
            raise e
            
    return {
        "id": "PASSWORD_POLICY",
        "title": "Password Policy Strength",
        "severity": "MEDIUM",
        "status": status,
        "detail": detail,
        "why_it_matters": "A strong password policy ensures that users create complex passwords that are harder to brute-force or guess."
    }
