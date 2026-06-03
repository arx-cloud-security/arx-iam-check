from datetime import datetime, timezone

def run_check(iam_client, cloudtrail_client):
    users = iam_client.list_users()["Users"]
    inactive_users = []
    now = datetime.now(timezone.utc)
    
    for user in users:
        username = user["UserName"]
        last_used = user.get("PasswordLastUsed")
        
        # Check keys
        keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
        key_last_used_dates = []
        for key in keys:
            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            if "LastUsedDate" in last_used_info["AccessKeyLastUsed"]:
                key_last_used_dates.append(last_used_info["AccessKeyLastUsed"]["LastUsedDate"])
        
        # Determine most recent activity
        dates = []
        if last_used: dates.append(last_used)
        dates.extend(key_last_used_dates)
        
        if not dates:
            # Never used
            create_date = user["CreateDate"]
            if (now - create_date).days > 90:
                inactive_users.append(username)
        else:
            most_recent = max(dates)
            if (now - most_recent).days > 90:
                inactive_users.append(username)
                
    status = "PASS" if not inactive_users else "FAIL"
    detail = "No inactive IAM users found (90+ days)" if status == "PASS" else f"{len(inactive_users)} users have been inactive for 90+ days: {', '.join(inactive_users[:3])}{'...' if len(inactive_users) > 3 else ''}"
    
    return {
        "id": "INACTIVE_USERS",
        "title": "Inactive IAM Users (90+ Days)",
        "severity": "MEDIUM",
        "status": status,
        "detail": detail,
        "why_it_matters": "Inactive accounts increase the attack surface and should be removed or disabled to follow the principle of least privilege."
    }
