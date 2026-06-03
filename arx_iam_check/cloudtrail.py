def run_check(iam_client, cloudtrail_client):
    trails = cloudtrail_client.describe_trails()["trailList"]
    logging_active = False
    
    for trail in trails:
        trail_name = trail["Name"]
        status = cloudtrail_client.get_trail_status(Name=trail_name)
        if status.get("IsLogging"):
            logging_active = True
            break
            
    status_str = "PASS" if logging_active else "FAIL"
    detail = "At least one active CloudTrail trail was found" if logging_active else "No active CloudTrail logging found in this account"
    
    return {
        "id": "CLOUDTRAIL",
        "title": "CloudTrail Disabled",
        "severity": "CRITICAL",
        "status": status_str,
        "detail": detail,
        "why_it_matters": "CloudTrail is essential for auditing and incident response, as it records all API calls made in your AWS account."
    }
