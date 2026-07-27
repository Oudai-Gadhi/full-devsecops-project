import hashlib


def generate_fingerprint(tool, data):
    """
    Creates stable identity for a security finding
    """

    if tool == "SEMGREP":

        base = (
            f"{data.get('rule_id')}|"
            f"{data.get('file_path')}|"
            f"{data.get('line_number')}"
        )


    elif tool.startswith("TRIVY"):

        # Trivy vulnerability (CVE based)
        if data.get("cve"):

            base = (
                f"{data.get('cve')}|"
                f"{data.get('package_name')}|"
                f"{data.get('installed_version')}|"
                f"{data.get('target')}"
            )

        # Trivy misconfiguration
        else:

            base = (
                f"{data.get('rule_id')}|"
                f"{data.get('resource')}|"
                f"{data.get('file_path')}"
            )


    elif tool == "GITLEAKS":

        base = (
            f"{data.get('rule_id')}|"
            f"{data.get('file')}|"
            f"{data.get('secret_type')}"
        )


    elif tool == "ZAP":

        base = (
            f"{data.get('url')}|"
            f"{data.get('parameter')}|"
            f"{data.get('alert')}"
        )


    else:

        base = str(data)


    return hashlib.sha256(base.encode()).hexdigest()
