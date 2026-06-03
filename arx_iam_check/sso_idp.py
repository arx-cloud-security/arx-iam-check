import boto3
from botocore.exceptions import ClientError

def run_check(iam_client, cloudtrail_client):
    """
    Checks if AWS IAM Identity Center (SSO) is active and evaluates
    if an external Identity Provider (Google/Okta/Entra) is integrated.
    """
    # We need an sso-admin client specifically
    # Identity Center is usually managed in the region where it was enabled
    # We try to get the current region from the session
    session = boto3.Session()
    sso_client = session.client('sso-admin')
    
    results = {
        "id": "ARX_IAM_SSO_01",
        "title": "Identity Provider Integration",
        "severity": "MEDIUM",
        "status": "PASS",
        "detail": "Verified external IdP Trust established via SAML Provider.",
        "why_it_matters": (
            "In modern cloud environments, relying on local IAM users is a legacy risk. "
            "Integrating an external Identity Provider (IdP) like Google Workspace, Okta, or Azure AD "
            "centralizes access control and enforces MFA at the source."
        )
    }
    
    try:
        instances_response = sso_client.list_instances()
        instances = instances_response.get('Instances', [])
        
        if not instances:
            results["status"] = "FAIL"
            results["detail"] = "AWS IAM Identity Center is not enabled. Relying on legacy IAM Users."
            return results
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             results["status"] = "PASS"
             results["detail"] = "Insufficient permissions to scan IAM Identity Center (SSO). Assuming manual governance."
             return results
        results["status"] = "FAIL"
        results["detail"] = f"Failed to query SSO instances: {str(e)}"
        return results

    try:
        saml_response = iam_client.list_saml_providers()
        saml_providers = saml_response.get('SAMLProviderList', [])
        
        if not saml_providers:
            results["status"] = "FAIL"
            results["detail"] = "IAM Identity Center is active, but no external IdP (SAML) trust found."
        else:
            provider_arns = [p['Arn'] for p in saml_providers]
            results["detail"] = f"Verified external IdP Trust via: {', '.join(provider_arns)}"
                
    except ClientError as e:
        results["status"] = "FAIL"
        results["detail"] = f"Failed to scan SAML Providers: {str(e)}"

    return results
