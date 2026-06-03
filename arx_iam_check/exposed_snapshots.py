import boto3
from botocore.exceptions import ClientError

def run_check(iam_client, cloudtrail_client):
    results = {
        "id": "ARX_BLIND_02",
        "title": "Publicly Exposed Data Snapshots",
        "severity": "CRITICAL",
        "status": "PASS",
        "detail": "No public EBS snapshots detected.",
        "why_it_matters": (
            "A public snapshot allows ANY AWS user in the world to copy your entire "
            "hard drive. This is a common way production databases or application secrets "
            "are leaked during 'debugging' sessions."
        )
    }

    ec2 = boto3.client('ec2')

    try:
        snapshots = ec2.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all'])['Snapshots']

        if snapshots:
            results["status"] = "FAIL"
            results["detail"] = f"Detected {len(snapshots)} snapshots shared with the public."

    except ClientError as e:
        results["status"] = "INFO"
        results["detail"] = f"Skipped snapshot scan: {str(e)}"

    return results
