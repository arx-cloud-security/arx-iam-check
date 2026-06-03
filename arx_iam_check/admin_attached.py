def run_check(iam_client, cloudtrail_client):
    users = iam_client.list_users()["Users"]
    admin_users = []
    
    for user in users:
        username = user["UserName"]
        is_admin = False
        
        # Check attached managed policies
        attached = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for policy in attached:
            if policy["PolicyName"] == "AdministratorAccess":
                is_admin = True
                break
        
        # Check inline policies if not already found
        if not is_admin:
            inline = iam_client.list_user_policies(UserName=username)["PolicyNames"]
            for policy_name in inline:
                policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict): statements = [statements]
                
                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*":
                        is_admin = True
                        break
                if is_admin: break
        
        if is_admin:
            admin_users.append(username)
            
    status = "PASS" if not admin_users else "FAIL"
    detail = "No users have direct-attached Administrator permissions" if status == "PASS" else f"{len(admin_users)} users have direct Administrator permissions: {', '.join(admin_users[:3])}{'...' if len(admin_users) > 3 else ''}"
    
    return {
        "id": "ADMIN_ATTACHED",
        "title": "Direct-Attached Admin Policies",
        "severity": "HIGH",
        "status": status,
        "detail": detail,
        "why_it_matters": "Permissions should be granted via groups or roles, not attached directly to users, to ensure consistency and ease of auditing."
    }
