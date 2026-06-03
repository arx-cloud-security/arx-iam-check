from datetime import datetime, timezone

def run_check(iam_client, cloudtrail_client):
    users = iam_client.list_users()["Users"]
    old_keys = []
    now = datetime.now(timezone.utc)
    
    for user in users:
        username = user["UserName"]
        keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                age_days = (now - key["CreateDate"]).days
                if age_days > 90:
                    old_keys.append(f"{username} ({age_days} days)")
                    
    status = "PASS" if not old_keys else "FAIL"
    detail = "No active access keys older than 90 days found" if status == "PASS" else f"{len(old_keys)} active keys are older than 90 days: {', '.join(old_keys[:3])}{'...' if len(old_keys) > 3 else ''}"
    
    return {
        "id": "ACCESS_KEY_AGE",
        "title": "Access Keys Older Than 90 Days",
        "severity": "HIGH",
        "status": status,
        "detail": detail,
        "why_it_matters": "Rotating access keys regularly reduces the window of opportunity for an attacker to use a compromised key."
    }
