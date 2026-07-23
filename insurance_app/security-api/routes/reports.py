from flask import Blueprint, request, jsonify
from db import get_conn
from services.parser import extract_findings
import os 
import json
from dotenv import load_dotenv
load_dotenv()
REPORT_API_KEY= os.environ["API_KEY"]
reports_bp = Blueprint("reports", __name__)
@reports_bp.route("/api/security/reports", methods=["POST"])
def ingest_report():

    data = request.json
    if request.headers.get("X-API-Key") != REPORT_API_KEY:
        return jsonify({"error": "unauthorized"}), 401


    conn = get_conn()
    cur = conn.cursor()

    # ---------------- DEPLOYMENT ----------------
    dep = data["deployment"]

    cur.execute("""
        INSERT INTO deployments (commit_sha, branch, github_run_id, status)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """, (
        dep["commit_sha"],
        dep["branch"],
        dep["github_run_id"],
        "SUCCESS"
    ))

    deployment_id = cur.fetchone()[0]

    # ---------------- SCANS ----------------
    for scan in data["scans"]:

        cur.execute("""
            INSERT INTO security_scans (
                deployment_id, tool,
                critical, high, medium, low,
                raw_report
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            deployment_id,
            scan["tool"],
            scan.get("critical", 0),
            scan.get("high", 0),
            scan.get("medium", 0),
            scan.get("low", 0),
            json.dumps(scan.get("report", {}))
        ))

        scan_id = cur.fetchone()[0]

        # ---------------- FINDINGS ----------------
        findings = extract_findings(scan)

        for f in findings:
            cur.execute("""
                INSERT INTO security_findings (
                    scan_id, tool, severity,
                    title, description,
                    file_path, line_number,
                    rule_id,
                    package_name, installed_version, fixed_version,
                    cve,
                    fingerprint,
                    status
                )
                VALUES (
                    %s,%s,%s,%s,%s,
                    %s,%s,%s,
                    %s,%s,%s,
                    %s,
                    %s,
                    'OPEN'
                )
                ON CONFLICT (fingerprint) DO UPDATE SET 
                    scan_id = EXCLUDED.scan_id,
                    updated_at = NOW() 
            """, (
                scan_id,
                f.get("tool"),
                f.get("severity"),
                f.get("title"),
                f.get("description"),
                f.get("file_path"),
                f.get("line_number"),
                f.get("rule_id"),
                f.get("package_name"),
                f.get("installed_version"),
                f.get("fixed_version"),
                f.get("cve"),
                f.get("fingerprint")
            ))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "status": "success",
        "deployment_id": deployment_id
    })
