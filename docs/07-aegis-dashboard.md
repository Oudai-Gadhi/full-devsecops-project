# 7. Aegis Dashboard (`dashboard/`)

A single-file Streamlit app (`app.py`, ~1230 lines) that acts as the human
control center for the whole DevSecOps loop: it's where an operator reviews
what CI found, decides what to do about it, watches the cluster, and
actually ships approved deployments.

> `dashboard/app1.py` is a larger (~1350 line) variant present in the repo.
> Treat `app.py` as the canonical, current version and `app1.py` as a
> parallel draft/backup unless you've confirmed otherwise in your own
> checkout — run a diff before relying on it.

## 7.1 What it does — three tabs

| Tab | Purpose |
|---|---|
| **Pods** | Live `kubectl get pods -n <namespace>` view for `devsecops` and `av-scanning`, per-pod Describe/Logs/Actions (including a restart button that runs `kubectl delete pod`) |
| **Security Findings** | Every deployment from `security-api`'s database, grouped, with per-finding triage (mark IGNORED / RISK_ACCEPTED / POSTPONED with a note), CSV export, an optional AI-generated fix suggestion, and a **Deploy** button |
| **AV Results** | Read-only view of the `scan_results` table from the AV/YARA scanner's Postgres database |

## 7.2 Authentication

- Custom login screen (`login_screen()`) against a `dashboard_users` table
  (bcrypt via `passlib`), **not** tied to the insurance app's own
  `admin_users` table — these are two entirely separate login systems.
- On success, a random 32-byte token is stored in a `dashboard_sessions`
  table and appended to the URL as `?token=...`, so a browser refresh
  doesn't force re-login (`restore_session_from_url()`). Sessions expire
  after `SESSION_LIFETIME_DAYS` (7 by default).
- Create the first user with `dashboard/create_admin.py` (interactive CLI,
  prompts for username/password, requires 8+ characters).

## 7.3 The "Deploy" button, precisely

This is the one feature that actually changes what's running:

1. Operator picks a deployment (identified by `commit_sha`) whose
   findings they've reviewed.
2. `update_image_tag()` opens the **local file** at
   `BACKEND_DEPLOYMENT_YAML` / `FRONTEND_DEPLOYMENT_YAML` (hardcoded paths
   — see below), regex-replaces the image tag for the matching
   `image: <repo>:` line with the new commit SHA, and writes the file back.
3. `kubectl_apply()` runs `kubectl apply -f <that file>`.
4. On success for both files, the `deployments` row is updated to
   `status='DEPLOYED'` with `deployed_at`/`deployed_by`, and the dashboard's
   cached data is invalidated so the UI reflects it immediately.

**Implication:** the dashboard must run on a machine that (a) has a local,
writable checkout of `k8s/backend/deployment.yaml` and
`k8s/frontend/deployment.yaml`, and (b) has a working `kubectl` context
pointed at your cluster. It edits real files on disk — treat that
directory as part of your deployment's source of truth, and consider
putting it under git so accidental edits are visible/revertible.

Before running this yourself, edit these constants near the top of
`app.py` to match your setup:

```python
BACKEND_IMAGE_REPO = "ghcr.io/<your-namespace>/backend"
FRONTEND_IMAGE_REPO = "ghcr.io/<your-namespace>/frontend"
BACKEND_DEPLOYMENT_YAML = "/path/to/your/checkout/k8s/backend/deployment.yaml"
FRONTEND_DEPLOYMENT_YAML = "/path/to/your/checkout/k8s/frontend/deployment.yaml"
```

## 7.4 The AI fix-suggestion feature (optional)

- Calls the Groq API (`llama-3.3-70b-versatile` by default) with a fixed
  system prompt (`INFRA_CONTEXT`) that hardcodes real facts about this
  specific stack (base images, non-root users, multi-stage build
  discarding the frontend's build tooling, etc.) so the model reasons
  about true/false-positive status instead of giving generic advice.
- Output format is deliberately constrained: one verdict line
  (`Verdict: True Positive` / `False Positive` + one grounded sentence),
  then up to 4 remediation steps — no other text.
- Cached for 24 hours per finding (`AI_FIX_TTL`), since the answer for a
  given finding rarely changes.
- If `GROQ_API_KEY` is unset, this feature is simply unavailable; nothing
  else in the dashboard depends on it.

## 7.5 Running it

No Dockerfile ships for this either — run it directly on a host with
`kubectl` access:

```bash
cd dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cat > .env << 'EOF'
PGHOST=localhost
PGPORT=5432
PGDATABASE=security_reports
PGUSER=security_api
PGPASSWORD=change_me
GROQ_API_KEY=your-groq-key   # optional
EOF

python3 create_admin.py       # first-time only: create your login
streamlit run app.py
```

By default Streamlit serves on `http://localhost:8501`.

## 7.6 Performance notes baked into the code

- `get_dashboard_data()` is a single joined query (deployments + scans +
  findings) rather than N+1 per-deployment queries, cached for
  `DASHBOARD_DATA_TTL` (15s).
- `kubectl` calls are cached separately and briefly (`PODS_TTL`/
  `KUBECTL_DETAIL_TTL`, 6s) since subprocess calls are the slowest part of
  the UI.
- The app deliberately avoids Streamlit's `st.tabs` for top-level
  navigation (a sidebar radio/page-key pattern is used instead) because
  `st.tabs` executes every tab's body on every rerun regardless of which
  tab is visible — that would fire `kubectl` subprocess calls even while
  looking at the Findings tab.

## 7.7 Putting it behind something other than `localhost:8501`

If you want the dashboard reachable by a team rather than just on your own
machine, put it behind a reverse proxy (nginx/Caddy) with authentication
at that layer too (Streamlit's own login is application-level, not a
substitute for network-level access control), and run it as a systemd
service or in a container you build yourself so it survives reboots.
