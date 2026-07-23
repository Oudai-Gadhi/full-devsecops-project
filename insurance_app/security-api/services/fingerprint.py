import hashlib

def generate_fingerprint(tool, data):
    """
    Creates stable identity for a vulnerability
    """

    if tool == "SEMGREP":
        base = f"{data.get('rule_id')}|{data.get('file_path')}|{data.get('line')}"
    
    elif tool.startswith("TRIVY"):
        base = f"{data.get('cve')}|{data.get('package')}|{data.get('installed_version')}"

    elif tool == "GITLEAKS":
        base = f"{data.get('rule_id')}|{data.get('file')}|{data.get('secret_type')}"

    elif tool == "ZAP":
        base = f"{data.get('url')}|{data.get('parameter')}|{data.get('alert')}"

    else:
        base = str(data)

    return hashlib.sha256(base.encode()).hexdigest()
