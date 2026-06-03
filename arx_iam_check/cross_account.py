import boto3
from botocore.exceptions import ClientError

def run_check(iam_client, cloudtrail_client):
    """
    Identifies IAM roles that can be assumed by accounts outside of the 
    current AWS Organization or a trusted list.
    """
    results = {
        "id": "ARX_BLIND_01",
        "title": "Cross-Account Trust Backdoors",
        "severity": "HIGH",
        "status": "PASS",
        "detail": "No untrusted cross-account relationships detected.",
        "why_it_matters": (
            "Cross-account roles allow external entities to access your environment. "
            "Startups often leave these open after a third-party audit or for old 'Dev-to-Prod' "
            "links, creating a silent backdoor that bypasses normal perimeter security."
        )
    }
    
    sts = boto3.client('sts')
    current_account_id = sts.get_caller_identity()['Account']
    
    findings = []
    try:
        roles = iam_client.list_roles()['Roles']
        for role in roles:
            policy = role.get('AssumeRolePolicyDocument', {})
            statements = policy.get('Statement', [])
            
            for statement in statements:
                principal = statement.get('Principal', {})
                aws_principal = principal.get('AWS', [])
                
                # Normalize to list
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                
                for p in aws_principal:
                    # Check if the principal is an external account ID
                    if ":" in p:
                        account_id = p.split(":")[4]
                        if account_id != current_account_id and account_id != "":
                             findings.append(f"Role '{role['RoleName']}' trusts external account: {account_id}")
                             
        if findings:
            results["status"] = "FAIL"
            results["detail"] = f"Detected {len(findings)} external trust relationships: {', '.join(findings[:3])}..."
            
    except ClientError as e:
        results["status"] = "ERROR"
        results["detail"] = f"Failed to scan roles: {str(e)}"

    return results
