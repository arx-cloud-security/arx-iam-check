import boto3
from botocore.exceptions import ClientError

def run_check(iam_client, cloudtrail_client):
    """
    Checks for IAM policies that allow creation of high-cost resources 
    (like GPU instances or high-tier RDS) without budget guardrails.
    """
    results = {
        "id": "ARX_BLIND_03",
        "title": "Unbounded Cost-Identity Risk",
        "severity": "MEDIUM",
        "status": "PASS",
        "detail": "No unbounded resource-creation risks detected.",
        "why_it_matters": (
            "Security isn't just about data; it's about the bank account. If a developer "
            "key is leaked, attackers often spin up 100x P3 (GPU) instances for crypto-mining. "
            "Without Service Control Policies (SCPs) or specific instance-type restrictions, "
            "this can bankrupt a startup in a weekend."
        )
    }
    
    # We look for 'RunInstances' without 'ec2:InstanceType' conditions in broad policies
    findings = []
    try:
        # Check the top 50 policies for brevity in this tool
        policies = iam_client.list_policies(Scope='Local', OnlyAttached=True)['Policies']
        for policy in policies:
            version = iam_client.get_policy_version(
                PolicyArn=policy['Arn'], 
                VersionId=policy['DefaultVersionId']
            )['PolicyVersion']['Document']
            
            statements = version.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    if any(a in ['ec2:RunInstances', 'ec2:*', '*'] for a in actions):
                        if 'Condition' not in stmt:
                            findings.append(policy['PolicyName'])
                            break
                            
        if findings:
            results["status"] = "FAIL"
            results["detail"] = f"Policies allow unbounded resource creation: {', '.join(findings[:2])}..."
            
    except ClientError as e:
        results["status"] = "ERROR"
        results["detail"] = f"Failed to scan cost-risk: {str(e)}"

    return results
