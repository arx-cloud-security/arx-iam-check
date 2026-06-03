import json
import os
from datetime import datetime, timezone

def write(findings, account_id, output_path="output/results.json"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    payload = {
        "account_id": account_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(findings),
        "findings": findings,
    }

    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
