# 1. Architecture Overview

## 1.1 System purpose

The project has two layers that are easy to conflate but serve different
purposes:

1. **The application layer** — an insurance accident-declaration web app
   (client form + admin dashboard) that a real end user interacts with.
2. **The DevSecOps layer** — everything that builds, scans, ships, and
   monitors layer 1: CI/CD pipeline, security scanners, a central findings
   database, an operator dashboard ("Aegis"), a file-scanning malware
   pipeline, and log/metric collection.

## 1.2 High-level diagram

```
 Developer
    │  git push (branch: main)
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ GitHub Actions ("Full DevSecOps Pipeline (CI/CD + Security)")       │
│                                                                       │
│  gitleaks ─┐                                                        │
│  semgrep   ├─► build-images ─► trivy-image ─► push-images (GHCR)    │
│  trivy-fs ─┘                                        │                │
│                                                       ├─► zap (frontend DAST) │
│                                                       └─► zap-backend (auth API DAST) │
│                                                              │        │
│                                            send-security-report      │
└─────────────────────────────────────────────┬──────────────────────┘
                                               │ HTTPS POST (X-API-Key)
                                               │ via ngrok tunnel
                                               ▼
                                 ┌───────────────────────────────┐
                                 │ security-api (Flask)          │
                                 │  /api/security/reports        │
                                 │  writes to PostgreSQL:        │
                                 │  deployments / security_scans │
                                 │  / security_findings          │
                                 └───────────────┬───────────────┘
                                                  │ reads
                                                  ▼
                                 ┌───────────────────────────────┐
                                 │ Aegis dashboard (Streamlit)   │
                                 │  - Security Findings triage   │
                                 │    (+ Groq AI fix suggestions)│
                                 │  - Pods (live kubectl view)   │
                                 │  - AV Results                 │
                                 │  - "Deploy" button → kubectl  │
                                 │    apply (bumps image tag)    │
                                 └───────────────┬───────────────┘
                                                  │ kubectl
                                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Kubernetes cluster (namespace: devsecops)                            │
│                                                                       │
│   Ingress (nginx + ModSecurity/OWASP CRS)                             │
│        │                                                             │
│   ┌────┴────┐        ┌─────────┐        ┌───────┐                    │
│   │ frontend│  ──►   │ backend │  ──►   │ mysql │                    │
│   │ (nginx) │        │(FastAPI)│        │       │                    │
│   └─────────┘        └────┬────┘        └───────┘                    │
│                            │ reads/writes uploaded files              │
│                            ▼                                         │
│                   NFS PVCs: scan-input / clean-output                │
└───────────────────────────┬───────────────────────────────────────────┘
                             │ shared NFS volume
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Kubernetes namespace: av-scanning                                     │
│   Pod "av-scanner" (3 containers): clamd + freshclam + watcher       │
│   Scans every file dropped by the backend, moves clean files to      │
│   clean-output, deletes flagged files, records every verdict in a    │
│   separate PostgreSQL database (av_scanner).                         │
└─────────────────────────────────────────────────────────────────────┘

              (separate) Loki + Promtail + kube-prometheus-stack
              for cluster-wide log/metric collection
```

## 1.3 Components at a glance

| Component | What it is | Tech stack | Where it runs |
|---|---|---|---|
| **insurance_app / backend** | Claims API: submit declarations, list/review claims, auth, file uploads, email notifications | FastAPI, SQLAlchemy, PyMySQL, JWT auth (cookie-based) | Docker container → Kubernetes (`devsecops` ns) |
| **insurance_app / frontend** | Client declaration form + admin dashboard SPA | React 18, TypeScript, Vite, Tailwind CSS, served by nginx | Docker container → Kubernetes (`devsecops` ns) |
| **MySQL** | Application database (claims, attachments, admin users) | MySQL 8.0 | Docker Compose locally / K8s Deployment (emptyDir volume — see gaps doc) |
| **security-api** | Ingests security scan JSON from CI, normalizes findings, stores in Postgres | Flask, psycopg2, PostgreSQL | Exposed to CI via an ngrok tunnel in this setup |
| **dashboard ("Aegis")** | Human operator control center: findings triage, live pod view, AV results, one-click deploy | Streamlit, psycopg2, subprocess+kubectl, Groq LLM API (optional AI remediation) | Runs on a host with `kubectl` access to the cluster |
| **k8s/av (AV/YARA scanner)** | Scans files written to a shared NFS "drop zone" with ClamAV + YARA, routes clean/flagged files, logs every verdict | Python (`clamd_scan.py`), YARA, Bash (`watcher.sh`), PostgreSQL | Kubernetes (`av-scanning` ns) |
| **Monitoring stack** | Cluster log aggregation and metrics | Loki, Promtail, kube-prometheus-stack (Prometheus only; Grafana/Alertmanager disabled in current values) | Kubernetes (namespace `monitoring`, via Helm) |

## 1.4 Data flow: a claim's life

1. A client submits a declaration (with optional file attachments) through
   the React frontend → `POST /api/claims` on the FastAPI backend.
2. The backend stores the claim in MySQL and the raw file under
   `backend/uploads` (Compose) or the mounted NFS `scan-input` share (K8s).
3. In the Kubernetes deployment, the AV/YARA watcher picks the file up from
   `scan-input`, scans it, and either moves it to `clean-output` (clean) or
   deletes it after logging the verdict to the `av_scanner` Postgres
   database (flagged/errored).
4. An admin reviews the claim in the frontend's `/admin` view, which calls
   `GET /api/claims`, `GET /api/attachments/{id}/file`, etc.
5. Status changes trigger an email to the client via SMTP
   (`send_status_email`, French-language notification for STAR Assurances).

## 1.5 Data flow: a code change's life (the DevSecOps loop)

1. Developer pushes to `main` in `insurance_app/`.
2. GitHub Actions runs SAST/secret/dependency scans in parallel
   (Gitleaks, Semgrep, Trivy filesystem scan).
3. If those complete, Docker images for frontend/backend are built, then
   scanned again as built images (Trivy image scan).
4. Images are pushed to GHCR (`ghcr.io/<owner>/<repo>/frontend|backend`)
   tagged `latest` and `<commit-sha>`.
5. OWASP ZAP runs a baseline DAST scan against the running frontend
   container, and a second, **authenticated** API scan against the backend
   (it seeds a temporary admin user, logs in, and replays the session
   cookie into ZAP).
6. All five tools' JSON reports are downloaded, merged, and POSTed to the
   `security-api` webhook, which persists them as one `deployment` +
   many `security_scans` + many `security_findings` rows.
7. An operator opens the **Aegis** dashboard, reviews new findings
   (optionally asking the built-in Groq-powered assistant for a fix), and,
   when satisfied, clicks **Deploy** — which bumps the image tag in
   `k8s/backend/deployment.yaml` / `k8s/frontend/deployment.yaml` to the new
   commit SHA and runs `kubectl apply -f`.

See [05-cicd-pipeline.md](05-cicd-pipeline.md) and
[07-aegis-dashboard.md](07-aegis-dashboard.md) for the full detail.
