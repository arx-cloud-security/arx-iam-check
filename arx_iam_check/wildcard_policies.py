import json

def run_check(iam_client, cloudtrail_client):
    policies = iam_client.list_policies(Scope='Local')["Policies"]
    wildcard_policies = []
    
    for policy in policies:
        arn = policy["Arn"]
        version_id = policy["DefaultVersionId"]
        version = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]
        document = version["Document"]
        
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        has_wildcard = False
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                action = stmt.get("Action", [])
                resource = stmt.get("Resource", [])
                
                if action == "*" or (isinstance(action, list) and "*" in action):
                    has_wildcard = True
                if resource == "*" or (isinstance(resource, list) and "*" in resource):
                    has_wildcard = True
            if has_wildcard:
                break
        
        if has_wildcard:
            wildcard_policies.append(policy["PolicyName"])
            
    status = "PASS" if not wildcard_policies else "FAIL"
    detail = "No customer-managed policies with broad wildcards found" if status == "PASS" else f"{len(wildcard_policies)} policies have broad wildcards: {', '.join(wildcard_policies[:3])}{'...' if len(wildcard_policies) > 3 else ''}"
    
    return {
        "id": "WILDCARD_POLICIES",
        "title": "Wildcard IAM Policies",
        "severity": "HIGH",
        "status": status,
        "detail": detail,
        "why_it_matters": "Wildcard permissions ('*') violate the principle of least privilege and can allow users to perform unintended actions."
    }
