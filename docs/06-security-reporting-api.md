# 6. Security Reporting API (`security-api`)

A small Flask service whose only job is: receive the merged security
report from CI, normalize every tool's findings into one schema, and store
everything in PostgreSQL so the Aegis dashboard can query it.

## 6.1 Files

```
insurance_app/security-api/
├── app.py                  # Flask app factory, registers the blueprint
├── config.py                # reads PG* env vars
├── db.py                     # psycopg2 connection helper
├── requirements.txt
└── routes/
│   └── reports.py            # POST /api/security/reports
└── services/
    ├── fingerprint.py         # stable per-finding hash (dedup key)
    └── parser.py               # per-tool finding extraction + severity normalization
```

## 6.2 Database schema (implied by the code — create these tables yourself)

`routes/reports.py` and `dashboard/app.py` together imply this schema.
There is no migration file for this API in the repo (unlike the AV
scanner, which ships `sql/schema.sql`), so create it manually before first
use:

```sql
CREATE TABLE deployments (
    id              SERIAL PRIMARY KEY,
    commit_sha      VARCHAR(64) NOT NULL,
    branch          VARCHAR(255),
    github_run_id   VARCHAR(64),
    status          VARCHAR(32) NOT NULL DEFAULT 'SUCCESS', -- SUCCESS / DEPLOYED
    created_at      TIMESTAMP DEFAULT NOW(),
    deployed_at     TIMESTAMP,
    deployed_by     VARCHAR(64)
);

CREATE TABLE security_scans (
    id              SERIAL PRIMARY KEY,
    deployment_id   INTEGER REFERENCES deployments(id),
    tool            VARCHAR(32) NOT NULL,   -- SEMGREP / TRIVY_FS / TRIVY_IMAGE / GITLEAKS / ZAP
    critical        INTEGER DEFAULT 0,
    high            INTEGER DEFAULT 0,
    medium          INTEGER DEFAULT 0,
    low             INTEGER DEFAULT 0,
    raw_report      JSONB
);

CREATE TABLE security_findings (
    id                  SERIAL PRIMARY KEY,
    scan_id             INTEGER REFERENCES security_scans(id),
    tool                VARCHAR(32),
    severity            VARCHAR(16),
    title               TEXT,
    description         TEXT,
    file_path           TEXT,
    line_number         INTEGER,
    rule_id             TEXT,
    package_name        TEXT,
    installed_version   TEXT,
    fixed_version       TEXT,
    cve                 TEXT,
    fingerprint         VARCHAR(64) UNIQUE NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'OPEN', -- OPEN / IGNORED / RISK_ACCEPTED / POSTPONED
    resolution_note     TEXT,
    resolved_by         VARCHAR(64),
    resolved_at         TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT NOW()
);
```

> `fingerprint` must be `UNIQUE` — `routes/reports.py` relies on
> `ON CONFLICT (fingerprint) DO UPDATE` to avoid duplicate rows for the
> same underlying vulnerability across repeated scans.

The `dashboard/schema.sql` file (in `dashboard/`, not `security-api/`)
adds the `dashboard_users`, `dashboard_sessions`, and the additive
`resolution_note`/`resolved_by`/`resolved_at`/`deployed_at`/`deployed_by`
columns — run it after the above (it uses `ADD COLUMN IF NOT EXISTS`, so
it's safe even if you already created those columns above).

## 6.3 How findings are normalized (`services/parser.py`)

`extract_findings(scan)` branches per tool:

| Tool | Source field it reads | Notes |
|---|---|---|
| `SEMGREP` | `report.results[]` | Severity mapped `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW` |
| `TRIVY*` (fs or image) | `report.Results[].Vulnerabilities[]` | Severity used as-is (Trivy already emits CRITICAL/HIGH/MEDIUM/LOW); `fixed_version` is what powers the dashboard's "always has a fix" assumption for AI remediation |
| `GITLEAKS` | `report.leaks[]` | Every leak is hardcoded `severity: HIGH` |
| `ZAP` | `report.site[].alerts[]` | Severity parsed out of ZAP's `riskdesc` string (e.g. `"Medium (Medium)"` → `MEDIUM`) |

## 6.4 Fingerprinting (`services/fingerprint.py`)

A SHA-256 hash of a tool-specific tuple, used purely for de-duplication
across repeated scans of the same underlying issue:

| Tool | Fingerprint basis |
|---|---|
| Semgrep | `rule_id \| file_path \| line` |
| Trivy | `cve \| package \| installed_version` |
| Gitleaks | `rule_id \| file \| secret_type` |
| ZAP | `url \| parameter \| alert` |

## 6.5 The ingest endpoint

`POST /api/security/reports`

- Requires header `X-API-Key: <matches API_KEY env var>` — returns `401`
  otherwise.
- Body: the `security-report.json` shape produced by
  `build_security_report.py` (see [05-cicd-pipeline.md](05-cicd-pipeline.md)).
- Inserts one `deployments` row, one `security_scans` row per tool, and
  one `security_findings` row per individual finding (upserting on
  `fingerprint`).
- Returns `{"status": "success", "deployment_id": <id>}`.

`GET /health` — simple liveness check, no auth.

## 6.6 Running it

There is no Dockerfile for `security-api` in the repo — run it directly:

```bash
cd insurance_app/security-api
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cat > .env << 'EOF'
PGHOST=localhost
PGPORT=5432
PGDATABASE=security_reports
PGUSER=security_api
PGPASSWORD=change_me
API_KEY=generate-a-long-random-value
EOF

python app.py     # dev server on 0.0.0.0:5000
```

For anything beyond local testing, put it behind a real WSGI server
(gunicorn/uwsgi) and a reverse proxy — Flask's built-in dev server (as
run by `app.run()`) is not meant for production traffic.

## 6.7 Exposing it to GitHub Actions

GitHub-hosted runners can't reach a service on your LAN directly. This
project's current setup uses **ngrok**:

```bash
ngrok config add-authtoken $YOUR_AUTHTOKEN
ngrok http --url=<API_URI>.dev 5000
```
AUTHTOKEN IS FOUND IN NGROK WEBAPP

Copy the resulting `https://<random>.ngrok-free.dev` URL into the
workflow's `env.API_URL` (pointing at `/api/security/reports`).


For a durable setup, replace the tunnel with either a self-hosted GitHub
Actions runner inside your network (no need to expose the API publicly
at all) or a properly firewalled public endpoint with TLS.
