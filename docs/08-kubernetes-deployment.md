# 8. Kubernetes Deployment — the app itself

This covers `k8s/namespace.yaml`, `k8s/backend/`, `k8s/frontend/`,
`k8s/mysql/`, `k8s/ingress.yaml`, `k8s/backend/app-nfs-storage.yaml`. The
AV/YARA scanner (`k8s/av/`) has its own document:
[09-av-yara-scanner.md](09-av-yara-scanner.md).

## 8.1 Manifest inventory

| File | Kind | Purpose |
|---|---|---|
| `namespace.yaml` | Namespace | Creates `devsecops` |
| `backend/deployment.yaml` | Deployment | Backend pod, 1 replica |
| `backend/service.yaml` | Service (ClusterIP) | Exposes backend on port 8000 |
| `backend/app-nfs-storage.yaml` | PV + PVC ×2 | `scan-input-nfs` / `clean-output-nfs`, backed by an external NFS server |
| `frontend/deployment.yaml` | Deployment | Frontend pod, 2 replicas, with readiness/liveness probes and resource limits |
| `frontend/service.yaml` | Service (ClusterIP) | Exposes frontend on port 80 → container port 8080 |
| `mysql/deployment.yaml` | Deployment | MySQL 8.0, 1 replica |
| `mysql/service.yaml` | Service (ClusterIP) | Exposes MySQL on port 3306 |
| `ingress.yaml` | Ingress | Routes `/api` → backend, `/` → frontend, on host `insurance.local`, with ModSecurity/OWASP CRS enabled |

## 8.2 Secrets these manifests expect to already exist

Create these **before** applying the Deployments (they reference them via
`secretKeyRef` / `imagePullSecrets`):

```bash
kubectl create namespace devsecops

# GHCR pull secret (use a GitHub PAT with read:packages scope as the password)
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<your-github-username> \
  --docker-password=<your-github-PAT> \
  -n devsecops

# MySQL credentials
kubectl create secret generic mysql-credentials \
  --from-literal=DB_USER=insurance_user \
  --from-literal=DB_PASSWORD='change_me_app' \
  --from-literal=DB_NAME=insurance \
  -n devsecops

# SMTP credentials
kubectl create secret generic smtp-credentials \
  --from-literal=SMTP_USER=your-mailbox@gmail.com \
  --from-literal=SMTP_PASSWORD='your-app-password' \
  -n devsecops

# Backend JWT signing secret
kubectl create secret generic backend-jwt-secret \
  --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
  -n devsecops
```

> Note `mysql/deployment.yaml` reuses the **same** `mysql-credentials`
> secret for `MYSQL_ROOT_PASSWORD` (mapped from `DB_PASSWORD`) and
> `MYSQL_DATABASE` (mapped from `DB_NAME`) — so the app's DB user password
> and the MySQL root password are the same value in this setup. Fine for a
> demo; give MySQL its own root secret before running this anywhere real.

## 8.3 Before you apply: edit the NFS server IP

`backend/app-nfs-storage.yaml` hardcodes an NFS server IP
(`192.168.221.135` in the checked-in file) for two `PersistentVolume`s
(`scan-input`, `clean-output`). Point both `nfs.server:` fields at your own
NFS server's IP and adjust `nfs.path:` if your exports differ.

Set up the NFS server itself first, e.g. on an Ubuntu host:

```bash
sudo apt install nfs-kernel-server
sudo mkdir -p /srv/nfs/scan-input /srv/nfs/scan-input-2
echo "/srv/nfs/scan-input <cluster-node-CIDR>(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
echo "/srv/nfs/scan-input-2 <cluster-node-CIDR>(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -ra
sudo systemctl restart nfs-kernel-server
```

## 8.4 Apply order

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/backend/app-nfs-storage.yaml
kubectl apply -f k8s/mysql/deployment.yaml
kubectl apply -f k8s/mysql/service.yaml
kubectl apply -f k8s/backend/deployment.yaml
kubectl apply -f k8s/backend/service.yaml
kubectl apply -f k8s/frontend/deployment.yaml
kubectl apply -f k8s/frontend/service.yaml
```

Before applying `backend/deployment.yaml` and `frontend/deployment.yaml`,
either leave the image tag as whatever your CI last pushed, or bump it
manually to a tag you know exists in your GHCR (both files ship pinned to
a specific commit SHA from the original author's runs — that image won't
exist in **your** registry until your own CI has pushed at least once).

## 8.5 Ingress controller + WAF

The Ingress assumes an **nginx ingress controller** is already installed
(`ingressClassName: nginx`) and that it supports the ModSecurity
annotations used:

```bash
minikube addons enable ingress          # if using minikube
# or, for any cluster:
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace
```

Confirm your ingress-nginx build was compiled with ModSecurity support
(the standard `ingress-nginx` image does support the
`enable-modsecurity`/`enable-owasp-core-rules` annotations used here) —
if you're using a different ingress controller, these three annotations
are nginx-ingress-specific and won't apply.

```bash
kubectl apply -f k8s/ingress.yaml
```

Then apply for local testing:

```bash
echo "$(minikube ip) insurance.local" | sudo tee -a /etc/hosts   # minikube
# or, for a cloud LoadBalancer:
# point insurance.local's DNS (or your hosts file) at the ingress's external IP
```

Visit `http://insurance.local`.

## 8.6 Verifying the deployment

```bash
kubectl -n devsecops get pods -w
kubectl -n devsecops get svc
kubectl -n devsecops logs deploy/backend
kubectl -n devsecops logs deploy/frontend
kubectl -n devsecops describe ingress insurance-ingress
```

Health checks:
- Frontend readiness/liveness probes hit `/` on port 8080 — a `Running`
  pod with `READY 1/1` means nginx is serving.
- Backend has no built-in probe in the current manifest — verify manually
  with `kubectl exec` + `curl localhost:8000/docs`, or add a probe
  yourself (see [12-troubleshooting-known-issues.md](12-troubleshooting-known-issues.md)).

## 8.7 Known limitation: MySQL uses `emptyDir`

`mysql/deployment.yaml` mounts `/var/lib/mysql` on an `emptyDir` volume —
**all data is lost if the MySQL pod is rescheduled or restarted.** This is
fine for a demo/POC; before anything real, switch to a `PersistentVolumeClaim`
backed by real storage (or move to a managed MySQL service).

## 8.8 Rolling out a new version manually (without the Aegis dashboard)

If you're not using the dashboard's Deploy button:

```bash
NEW_TAG=$(git rev-parse HEAD)   # or whatever commit SHA CI just pushed
sed -i "s|\(image: ghcr.io/.*/backend:\)[a-f0-9]*|\1${NEW_TAG}|" k8s/backend/deployment.yaml
sed -i "s|\(image: ghcr.io/.*/frontend:\)[a-f0-9]*|\1${NEW_TAG}|" k8s/frontend/deployment.yaml
kubectl apply -f k8s/backend/deployment.yaml
kubectl apply -f k8s/frontend/deployment.yaml
kubectl -n devsecops rollout status deployment/backend
kubectl -n devsecops rollout status deployment/frontend
```
