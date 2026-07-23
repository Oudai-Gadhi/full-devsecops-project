import json
import os

def load(file):
    try:
        with open(file) as f:
            return json.load(f)
    except:
        return {}
gitleaks_data = load("gitleaks.json")
# If gitleaks output is a native list, wrap it. If it's already an empty dict {}, change it.
gitleaks_report = {"leaks": gitleaks_data} if isinstance(gitleaks_data, list) else {"leaks": []}
report = {
    "deployment": {
        "commit_sha": os.getenv("COMMIT_SHA"),
        "branch": os.getenv("BRANCH"),
        "github_run_id": os.getenv("RUN_ID")
    },

    "scans": [
        {"tool": "SEMGREP", "report": load("semgrep.json")},
        {"tool": "TRIVY_FS", "report": load("trivy-fs.json")},
        {"tool": "TRIVY_IMAGE", "report": load("trivy-image.json")},
        {"tool": "GITLEAKS", "report": gitleaks_report},
        {"tool": "ZAP", "report": load("zap.json")}
    ]
}

with open("security-report.json", "w") as f:
    json.dump(report, f, indent=2)

print("report generated")
