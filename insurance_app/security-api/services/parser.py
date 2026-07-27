from services.fingerprint import generate_fingerprint




def normalize_severity(tool, raw):
    raw = (raw or "").upper()
    if tool == "SEMGREP":
        return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw, "LOW")
    if tool == "ZAP":
        return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"}.get(raw, "INFO")
    # TRIVY and GITLEAKS already use CRITICAL/HIGH/MEDIUM/LOW natively
    return raw or "LOW"









def extract_findings(scan):

    tool = scan["tool"]
    report = scan.get("report", {})

    findings = []

    # ---------------- SEMGREP ----------------
    if tool == "SEMGREP":
        for r in report.get("results", []):
            raw_sev = r.get("extra", {}).get("severity", "INFO")
            findings.append({
                "tool": tool,
                "severity": normalize_severity(tool, raw_sev),
                "title": r.get("check_id"),
                "description": r.get("extra", {}).get("message"),
                "file_path": r.get("path"),
                "line_number": r.get("start", {}).get("line"),
                "rule_id": r.get("check_id"),
                "fingerprint": generate_fingerprint(tool, {
                    "rule_id": r.get("check_id"),
                    "file_path": r.get("path"),
                    "line": r.get("start", {}).get("line")
                })
            })

    # ---------------- TRIVY ----------------
    elif tool.startswith("TRIVY"):
        for r in report.get("Results", []):
            for v in r.get("Vulnerabilities", []):
            # Trivy image / fs
                findings.append({
                    "tool": tool,
                    "severity": v.get("Severity"),
                    "title": v.get("Title"),
                    "description": v.get("Description"),
                    "package_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "cve": v.get("VulnerabilityID"),
                    "fingerprint": generate_fingerprint(tool, {
                        "cve": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "installed_version": v.get("InstalledVersion")
                    })
                })
            # Trivy k8s-config
            print("TRIVY RESULTS KEYS", r.keys())
            print("TARGET:", r.get("Target"))
            print("MISCONF COUNT:", len(r.get("MISCONFIG",[])))
            for m in r.get("Misconfigurations", []):
              cause = m.get("CauseMetadata", {})
              findings.append({
                  "tool": tool,
                  "severity": m.get("Severity"),
                  "title": m.get("Title"),
                  "description": m.get("Message") or m.get("Description"),
                  "package_name": None,
                  "installed_version": None,
                  "fixed_version": None,
                  "cve": m.get("ID"),
                  "type": "misconfiguration",
                  "file_path": r.get("Target"),
                  "line_number": cause.get("StartLine"),
                  "fingerprint": generate_fingerprint(tool, {
                      "id": m.get("ID"),
                      "file_path": r.get("Target"),
                      "resource": m.get("Message")
                  })
              })


    # ---------------- GITLEAKS ----------------
    elif tool == "GITLEAKS":
        for r in report.get("leaks", []):
            findings.append({
                "tool": tool,
                "severity": "HIGH",
                "title": r.get("description"),
                "file_path": r.get("file"),
                "rule_id": r.get("rule"),
                "fingerprint": generate_fingerprint(tool, {
                    "rule_id": r.get("rule"),
                    "file": r.get("file"),
                    "secret_type": r.get("description")
                })
            })

    # ---------------- ZAP ----------------
    elif tool == "ZAP":
        for a in report.get("site", []):
            for alert in a.get("alerts", []):
                raw_sev = alert.get("riskdesc", "").split(" ")[0]  # "Medium (Medium)" -> "Medium"
                findings.append({
                    "tool": tool,
                    "severity": normalize_severity(tool, raw_sev),
                    "title": alert.get("name"),
                    "description": alert.get("desc"),
                    "url": alert.get("instances", [{}])[0].get("uri"),
                    "fingerprint": generate_fingerprint(tool, {
                        "url": alert.get("instances", [{}])[0].get("uri"),
                        "alert": alert.get("name")
                    })
                })

    return findings
