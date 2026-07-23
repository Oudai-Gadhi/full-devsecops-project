# 2. Prerequisites

Different parts of this project need different subsets of these. If you
only want the web app running locally, you need far less than the full
stack (see the "minimum for X" callouts below).

## 2.1 Accounts

| Account | Needed for |
|---|---|
| GitHub account with a fork/copy of this repo | CI/CD pipeline, GHCR image hosting |
| GHCR (GitHub Container Registry) access | Pulling images into Kubernetes (`ghcr-secret`) — uses your GitHub token, no separate signup |
| Groq API key (optional) | AI-assisted fix suggestions in the Aegis dashboard's Security Findings tab. Get one at https://console.groq.com — the dashboard runs fine without it, that feature just won't produce output |
| SMTP credentials (e.g. a Gmail app password) | Backend email notifications to claimants |
| ngrok account (or any reverse tunnel / public endpoint) | Exposing `security-api` so GitHub Actions (running on GitHub's infrastructure) can reach it. In production, replace this with a real public endpoint or a self-hosted runner inside your network — ngrok is a dev/demo convenience, not a production pattern |

## 2.2 Local tooling

| Tool | Version tested | Needed for |
|---|---|---|
| Docker + Docker Compose | Docker Engine with Compose v2 | Local app run, building images, AV scanner image |
| `kubectl` | Compatible with your cluster's API version | All Kubernetes steps, the Aegis dashboard's Pods/Deploy features |
| Kubernetes cluster | minikube (docker driver) was used for this project | Running the app, AV scanner, monitoring stack |
| Helm 3 | any recent 3.x | Installing Loki, Promtail, kube-prometheus-stack |
| Python 3.11 | matches backend base image | Running `security-api` and the `dashboard` outside containers |
| Node.js 20 | matches frontend build stage | Frontend local dev (`npm run dev`) outside Docker |
| PostgreSQL | any recent version, 2 databases needed (`security-api` DB and the AV scanner's `av_scanner` DB) | Security findings storage, AV scan results storage |
| NFS server (`nfs-kernel-server` or equivalent) | any | Shared `scan-input` / `clean-output` volumes between the backend and the AV scanner |
| `yara` CLI (bundled into the watcher image already) | — | Only needed inside the AV watcher container, not on your host |

## 2.3 Minimum for just running the app locally

You only need:
- Docker + Docker Compose

Everything else (Kubernetes, the AV scanner, the security pipeline, the
Aegis dashboard, monitoring) is optional infrastructure around the app. See
[04-local-development-insurance-app.md](04-local-development-insurance-app.md).

## 2.4 Minimum for the full production-style deployment

- A Kubernetes cluster you control (minikube is fine for a single-node
  demo; anything real needs a managed or self-hosted multi-node cluster)
- An NFS server reachable from that cluster
- A PostgreSQL instance reachable from both GitHub Actions' network path
  (via the `security-api` webhook) and from wherever the AV scanner runs
- Helm 3 for the monitoring stack
- A place to run the `security-api` Flask app and the `dashboard` Streamlit
  app persistently (a VM, a small always-on host, or containerize them
  yourself — neither ships with its own Dockerfile/K8s manifest in this
  repo, they're designed to run directly on a host with `kubectl` and
  network access)

## 2.5 Network/IP facts you will need to know ahead of time

Several manifests and configs in this repo hardcode IPs/hostnames that are
specific to the original author's environment and **must be changed**
before you deploy:

- `k8s/backend/app-nfs-storage.yaml` — NFS server IP (`192.168.221.135` in
  the repo)
- `k8s/av/manifests/10-storage.yaml` — same NFS server, `CHANGE_ME_NFS_SERVER_IP`
  placeholder in the AV scanner's PV definitions
- `k8s/ingress.yaml` — `host: insurance.local` (add to `/etc/hosts` for
  local testing, or replace with your real DNS name)
- CI workflow `env.API_URL` — the ngrok URL for `security-api`; you'll
  generate your own when you start your own tunnel
