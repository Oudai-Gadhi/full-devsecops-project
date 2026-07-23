# 11. Full Deployment Walkthrough (Start to Finish)

This is the single guide to follow if you want the **entire** project
running: the app, the CI/CD security pipeline, the central findings
database, the Aegis dashboard, the AV/YARA scanner, and monitoring.

Each phase links back to its detailed document — this page focuses on
**order of operations** and the exact commands to run.

Estimated time: 2–4 hours for a first-time single-node (minikube) setup,
mostly waiting on image pulls and Helm installs.

---

## Phase 0 — Decide your topology

You need, at minimum, three hosts/VMs (can be fewer if you're comfortable
co-locating things, e.g. all on one beefy VM for a demo):

1. **Kubernetes cluster** (minikube is fine for a demo)
2. **A host for NFS + PostgreSQL** (the original setup puts both on the
   same VM as minikube itself — fine for a demo, split them for anything
   real)
3. **A host to run `security-api` and the `dashboard`** (needs `kubectl`
   configured against your cluster, and network access to Postgres)

Full prerequisite list: [02-prerequisites.md](02-prerequisites.md).

---

## Phase 1 — Get the code

```bash
git clone <your-fork-url> full-devsecops-project
cd full-devsecops-project
```

---

## Phase 2 — Stand up shared infrastructure

**2.1 PostgreSQL** (one instance, two databases)

```bash
sudo apt install postgresql
sudo -u postgres psql <<'SQL'
CREATE DATABASE security_reports;
CREATE USER security_api WITH PASSWORD 'change_me';
GRANT ALL PRIVILEGES ON DATABASE security_reports TO security_api;

CREATE DATABASE av_scanner;
CREATE USER av_scanner_user WITH PASSWORD 'change_me_too';
GRANT ALL PRIVILEGES ON DATABASE av_scanner TO av_scanner_user;
SQL
```

Load the schemas:

```bash
# security_reports DB — create the tables from 06-security-reporting-api.md §6.2
psql -h <PG_HOST> -U security_api -d security_reports -f <(cat <<'EOF'
-- paste the CREATE TABLE statements from docs/06-security-reporting-api.md §6.2
EOF
)
psql -h <PG_HOST> -U security_api -d security_reports -f dashboard/schema.sql

# av_scanner DB
psql -h <PG_HOST> -U av_scanner_user -d av_scanner -f k8s/av/sql/schema.sql
```

Make sure `pg_hba.conf` allows connections from: your Kubernetes pod
network CIDR (for the AV scanner), and wherever `security-api`/`dashboard`
run. (This exact issue is documented as a real problem the original author
hit — see [09-av-yara-scanner.md](09-av-yara-scanner.md) §9.5 gap
discussion / `k8s/av/readme.md` §8, problem 7.)

**2.2 NFS server**

```bash
sudo apt install nfs-kernel-server
sudo mkdir -p /srv/nfs/scan-input /srv/nfs/scan-input-2
echo "/srv/nfs/scan-input <cluster-CIDR>(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
echo "/srv/nfs/scan-input-2 <cluster-CIDR>(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -ra && sudo systemctl restart nfs-kernel-server
```

Full detail: [08-kubernetes-deployment.md](08-kubernetes-deployment.md) §8.3.

---

## Phase 3 — Kubernetes cluster baseline

```bash
minikube start --driver=docker
minikube addons enable ingress

kubectl create namespace devsecops
```

Create the four required Secrets (GHCR pull, MySQL, SMTP, JWT) — full
commands in [08-kubernetes-deployment.md](08-kubernetes-deployment.md) §8.2.

---

## Phase 4 — Wire up the CI/CD pipeline

1. Push this repo to your own GitHub remote.
2. Add repo secrets `API_KEY` (invent a long random value — you'll reuse
   it in Phase 5) and `ZAP_JWT` (another random value).
3. **Don't push to `main` yet** — `security-api` needs to be reachable
   first, or the final reporting job will just fail to POST (harmless,
   but you won't get findings recorded).

Full detail: [05-cicd-pipeline.md](05-cicd-pipeline.md).

---

## Phase 5 — Stand up `security-api`

```bash
cd insurance_app/security-api
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cat > .env << 'EOF'
PGHOST=<your-pg-host>
PGPORT=5432
PGDATABASE=security_reports
PGUSER=security_api
PGPASSWORD=change_me
API_KEY=<the same value you put in the GitHub secret>
EOF

python app.py
```

Expose it to GitHub Actions:

```bash
ngrok http 5000
```

Copy the `https://...ngrok-free.dev` URL, update `env.API_URL` in
`insurance_app/.github/workflows/build-and-push.yml` to
`<that-url>/api/security/reports`, commit, and push.

Full detail: [06-security-reporting-api.md](06-security-reporting-api.md).

---

## Phase 6 — First CI run

```bash
git add insurance_app/.github/workflows/build-and-push.yml
git commit -m "point pipeline at our security-api"
git push origin main
```

Watch the **Actions** tab. Expect ~5–10 minutes for all jobs. At the end,
confirm:
- Two images exist in your GHCR packages (`frontend`, `backend`)
- `security-api`'s logs show a `POST /api/security/reports` returning 200
- A row now exists in your `deployments` table:
  `psql ... -c "SELECT * FROM deployments;"`

If it fails, see [12-troubleshooting-known-issues.md](12-troubleshooting-known-issues.md).

---

## Phase 7 — Deploy the app to Kubernetes

```bash
NEW_TAG=$(git rev-parse HEAD)
sed -i "s|\(image: ghcr.io/.*/backend:\)[a-f0-9]*|\1${NEW_TAG}|" k8s/backend/deployment.yaml
sed -i "s|\(image: ghcr.io/.*/frontend:\)[a-f0-9]*|\1${NEW_TAG}|" k8s/frontend/deployment.yaml
# also update the NFS server IP in k8s/backend/app-nfs-storage.yaml first!

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/backend/app-nfs-storage.yaml
kubectl apply -f k8s/mysql/deployment.yaml -f k8s/mysql/service.yaml
kubectl apply -f k8s/backend/deployment.yaml -f k8s/backend/service.yaml
kubectl apply -f k8s/frontend/deployment.yaml -f k8s/frontend/service.yaml
kubectl apply -f k8s/ingress.yaml

kubectl -n devsecops get pods -w
```

Add `insurance.local` to `/etc/hosts` pointing at `minikube ip`, then visit
`http://insurance.local`.

Full detail: [08-kubernetes-deployment.md](08-kubernetes-deployment.md).

---

## Phase 8 — Deploy the AV/YARA scanner

```bash
psql -h <PG_HOST> -U av_scanner_user -d av_scanner -f k8s/av/sql/schema.sql   # if not already done in Phase 2

eval $(minikube docker-env)
docker build -f k8s/av/Dockerfile.watcher -t av-watcher:latest k8s/av/

# edit k8s/av/manifests/10-storage.yaml (NFS IP), 25-secret.yaml (Postgres creds),
# 20-configmaps.yaml (real YARA rules) before applying

kubectl apply -f k8s/av/manifests/00-namespace.yaml
kubectl apply -f k8s/av/manifests/10-storage.yaml
kubectl apply -f k8s/av/manifests/20-configmaps.yaml
kubectl apply -f k8s/av/manifests/25-secret.yaml
kubectl apply -f k8s/av/manifests/30-deployment.yaml
kubectl apply -f k8s/av/manifests/40-networkpolicy.yaml

kubectl -n av-scanning get pods -w
```

Test it:

```bash
curl -s https://secure.eicar.org/eicar.com.txt -o /srv/nfs/scan-input/eicar-test.txt
# wait ~10s, then confirm it's gone from scan-input and flagged in Postgres:
psql -h <PG_HOST> -U av_scanner_user -d av_scanner -c \
  "SELECT file_name, overall_status FROM scan_results ORDER BY scanned_at DESC LIMIT 5;"
```

Full detail: [09-av-yara-scanner.md](09-av-yara-scanner.md).

---

## Phase 9 — Stand up the Aegis dashboard

```bash
cd dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cat > .env << 'EOF'
PGHOST=<your-pg-host>
PGPORT=5432
PGDATABASE=security_reports
PGUSER=security_api
PGPASSWORD=change_me
GROQ_API_KEY=          # optional
EOF

python3 create_admin.py    # create your login
```

Before starting it, edit these constants near the top of `app.py`:

```python
BACKEND_IMAGE_REPO = "ghcr.io/<your-namespace>/backend"
FRONTEND_IMAGE_REPO = "ghcr.io/<your-namespace>/frontend"
BACKEND_DEPLOYMENT_YAML = "/absolute/path/to/full-devsecops-project/k8s/backend/deployment.yaml"
FRONTEND_DEPLOYMENT_YAML = "/absolute/path/to/full-devsecops-project/k8s/frontend/deployment.yaml"
```

Make sure `kubectl` on this host is pointed at your cluster
(`kubectl config current-context`), then:

```bash
streamlit run app.py
```

Open `http://localhost:8501`, log in, and check all three tabs: Pods (you
should see your `devsecops` and `av-scanning` pods), Security Findings
(the deployment from Phase 6 should appear), AV Results (the EICAR test
from Phase 8 should appear as `FLAGGED`).

Full detail: [07-aegis-dashboard.md](07-aegis-dashboard.md).

---

## Phase 10 — Monitoring stack (optional but recommended)

```bash
kubectl create namespace monitoring
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring -f k8s/values.yaml
helm install loki grafana/loki -n monitoring -f k8s/loki-values.yaml
helm install promtail grafana/promtail -n monitoring -f k8s/promtail-values.yaml

kubectl -n monitoring get pods
```

Full detail: [10-monitoring-logging.md](10-monitoring-logging.md).

---

## Phase 11 — Full loop test

1. Make a trivial code change in `insurance_app/backend` or `frontend`.
2. Push to `main` → watch the pipeline run end-to-end (Phase 4-6 flow).
3. Open the Aegis dashboard's **Security Findings** tab — confirm the new
   deployment and its findings appear.
4. Triage a finding (or just review it), then click **Deploy**.
5. Confirm in the **Pods** tab (or `kubectl -n devsecops get pods`) that
   new pods rolled out with the new image tag.
6. Submit a test claim with a file attachment through the running app at
   `http://insurance.local`, and confirm in the **AV Results** tab that it
   was scanned.

If every step above works, the full system is running end-to-end.

---

## What you've built, in summary

```
push → scan (5 tools) → build+push images → DAST (auth'd) → central report
  → Aegis triage → deploy → running app (backend+frontend+mysql)
  → uploads scanned by AV/YARA pipeline → everything logged to Loki/Prometheus
```
