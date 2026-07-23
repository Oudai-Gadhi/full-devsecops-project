# 3. Environment Variables & Secrets Reference

This is a single reference for every environment variable / secret used
anywhere in the project, grouped by service. Treat every value below marked
**secret** as something that must never be committed to git in real form —
several manifests in the repo ship with obvious placeholders for exactly
this reason.

## 3.1 `insurance_app` — backend (FastAPI)

Set via `docker-compose.yml` (local) or Kubernetes `Secret`s (cluster).

| Variable | Purpose | Secret? |
|---|---|---|
| `DATABASE_URL` | Full SQLAlchemy connection string, e.g. `mysql+pymysql://user:pass@host:3306/db` | yes |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | Individual MySQL connection parts (used in K8s to compose `DATABASE_URL`) | yes (user/password) |
| `SMTP_SERVER` | e.g. `smtp.gmail.com` | no |
| `SMTP_PORT` | e.g. `587` | no |
| `SMTP_USER` | Sending mailbox address | yes |
| `SMTP_PASSWORD` | Mailbox app password | yes |
| `JWT_SECRET` | Signs the admin session JWT/cookie | yes |
| `COOKIE_SECURE` | `"true"`/`"false"` — set to `true` once serving over HTTPS | no |
| `SCAN_INPUT_DIR` | Path where uploaded files are written for AV scanning (`/mnt/scan-input` in K8s) | no |
| `CLEAN_OUTPUT_DIR` | Path where clean files reappear after scanning (`/mnt/clean-output` in K8s) | no |

## 3.2 `insurance_app` — MySQL

| Variable | Purpose |
|---|---|
| `MYSQL_ROOT_PASSWORD` | Root password (Compose) |
| `MYSQL_DATABASE` | Database name |
| `MYSQL_USER` / `MYSQL_PASSWORD` | App-level DB user (Compose) |

In Kubernetes these are sourced from a `mysql-credentials` Secret with keys
`DB_USER`, `DB_PASSWORD`, `DB_NAME` (also reused for `MYSQL_ROOT_PASSWORD`
and `MYSQL_DATABASE` in `k8s/mysql/deployment.yaml`).

## 3.3 CI/CD pipeline (`.github/workflows/build-and-push.yml`)

| Secret / var | Purpose |
|---|---|
| `secrets.GITHUB_TOKEN` | Auto-provided by GitHub Actions; used to log into GHCR and push images | 
| `secrets.API_KEY` | Shared key sent as `X-API-KEY` header when POSTing the merged security report to `security-api` |
| `secrets.ZAP_JWT` | JWT secret used when spinning up a throwaway backend container for the authenticated ZAP API scan |
| `env.API_URL` | Public URL of the `security-api` webhook (an ngrok tunnel in the current setup) |

## 3.4 `security-api` (Flask)

| Variable | Purpose | Secret? |
|---|---|---|
| `PGHOST` | Postgres host | no |
| `PGPORT` | Postgres port (default `5432`) | no |
| `PGDATABASE` | Database name | no |
| `PGUSER` | Postgres user | yes |
| `PGPASSWORD` | Postgres password | yes |
| `API_KEY` | Must match the CI secret above; requests without a matching `X-API-Key` header are rejected with 401 | yes |

## 3.5 `dashboard` (Aegis, Streamlit)

Loaded from a `.env` file next to `app.py`.

| Variable | Purpose | Secret? |
|---|---|---|
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | Connects to the **same** Postgres database as `security-api` (reads deployments/scans/findings) | yes (user/password) |
| `GROQ_API_KEY` | Enables the "AI fix suggestion" button on findings. Omit to disable that feature only | yes |
| `GROQ_MODEL` | Defaults to `llama-3.3-70b-versatile` | no |

Hardcoded in `app.py` (edit these constants directly for your environment,
they are not env vars):
- `BACKEND_IMAGE_REPO` = `ghcr.io/oudai-gadhi/cloud-native-claims-platform/backend`
- `FRONTEND_IMAGE_REPO` = `ghcr.io/oudai-gadhi/cloud-native-claims-platform/frontend`
- `BACKEND_DEPLOYMENT_YAML` = `/home/oudai/k8s/backend/deployment.yaml`
- `FRONTEND_DEPLOYMENT_YAML` = `/home/oudai/k8s/frontend/deployment.yaml`
- `NAMESPACES` = `["devsecops", "av-scanning"]`

> Change the image repo constants and the deployment YAML paths to match
> your own GHCR namespace and the actual path where you keep the `k8s/`
> folder on the machine running the dashboard — the "Deploy" button
> literally opens and edits those files then shells out to `kubectl apply`.

## 3.6 AV/YARA scanner (`k8s/av`)

Set via `manifests/25-secret.yaml` (Postgres) and env vars on the `watcher`
container.

| Variable | Purpose | Secret? |
|---|---|---|
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | Connects to a **separate** Postgres database, `av_scanner` (not the same DB as `security-api`) | yes |
| `SCAN_DIR` | Drop-zone path inside the container (mounted NFS `scan-input`) | no |
| `CLEAN_DIR` | Clean-output path inside the container (mounted NFS `clean-output`) | no |
| `YARA_RULES` | Path to the mounted YARA rules ConfigMap | no |
| `POLL_INTERVAL_SECONDS` | Polling frequency (default 5s) — tune against NFS load | no |
| `CLAMD_SOCKET_HOST`, `CLAMD_SOCKET_PORT` | Where `clamd` is listening (localhost:3310, same pod) | no |

## 3.7 Quick checklist — secrets you must create yourself before deploying

- [ ] GitHub repo secrets: `API_KEY`, `ZAP_JWT` (plus `GITHUB_TOKEN` is automatic)
- [ ] Kubernetes secret `ghcr-secret` (image pull secret for GHCR) in the `devsecops` namespace
- [ ] Kubernetes secret `mysql-credentials` (`DB_USER`, `DB_PASSWORD`, `DB_NAME`) in `devsecops`
- [ ] Kubernetes secret `smtp-credentials` (`SMTP_USER`, `SMTP_PASSWORD`) in `devsecops`
- [ ] Kubernetes secret `backend-jwt-secret` (`JWT_SECRET`) in `devsecops`
- [ ] Postgres database + user for `security-api`
- [ ] Postgres database + user for the AV scanner (`av_scanner`), plus `manifests/25-secret.yaml` filled in and applied
- [ ] `.env` file for `dashboard/app.py` (Postgres creds + optional `GROQ_API_KEY`)
- [ ] `.env` file for `insurance_app/backend` and `insurance_app` Compose (`.env` referenced by `docker-compose.yml`)
