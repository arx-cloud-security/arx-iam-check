import botocore.exceptions

def handle(e):
    if isinstance(e, botocore.exceptions.NoCredentialsError):
        print("\n❌ AWS credentials not found.")
        print("   → Run 'aws sts get-caller-identity' to confirm your CLI is configured.")
    elif isinstance(e, botocore.exceptions.ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException"):
            action = e.response.get("Error", {}).get("Message", "unknown action")
            print(f"\n❌ Access denied: {action}")
            print('   → Your credentials lack the required permissions.')
            print('   → See README.md → "What Permissions Does It Need?"')
        elif code == "ExpiredTokenException":
            print("\n❌ Session expired.")
            print("   → Re-authenticate with your SSO/MFA and try again.")
        else:
            raise e
    else:
        raise e
