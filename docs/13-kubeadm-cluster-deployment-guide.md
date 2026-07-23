# 13. From `git clone` to a Working Kubernetes Cluster (1 Control Plane + 1 Worker Node) — Complete Step-by-Step Guide

This is a **self-contained** guide: everything from cloning the repo to a
fully running application on a real `kubeadm` cluster with one control-plane
node and one worker node (as opposed to the single-node `minikube` shortcuts
used elsewhere in this `docs/` folder). It ends with a troubleshooting
section covering the failure modes people actually hit doing this.

If you only need a quick single-node demo, `minikube` (see
[11-full-deployment-walkthrough.md](11-full-deployment-walkthrough.md)) is
faster. Use **this** guide when you want a real 2-node cluster — closer to
how the app would run in production.

---

## 13.1 What you'll end up with

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│  NODE 1 — control-plane      │        │  NODE 2 — worker             │
│  kube-apiserver, etcd,        │◄──────►│  kubelet, kube-proxy         │
│  controller-manager,          │        │  Application pods run here   │
│  scheduler                    │        │  (backend, frontend, mysql,  │
│  (by default, workloads       │        │   av-scanner)                 │
│  don't schedule here)          │        │                              │
└─────────────────────────────┘        └─────────────────────────────┘
        Flannel CNI (pod network 10.244.0.0/16) across both nodes
```

Both nodes join a single cluster over their private network. Everything
from Phase 2 onward in
[11-full-deployment-walkthrough.md](11-full-deployment-walkthrough.md)
(NFS, Postgres, secrets, app manifests, AV scanner, monitoring) applies
unchanged once the cluster itself exists — this guide's job is to get you
a real, working `kubectl get nodes` showing 2 `Ready` nodes, which is the
prerequisite everything else builds on.

> **Why Flannel specifically?** The AV scanner's own build notes
> (`k8s/av/readme.md` §8, problem 7) document a real issue the original
> author hit with the pod network being `10.244.0.0/16` under Flannel, as
> distinct from the node network. Using Flannel here keeps your cluster
> consistent with that documented behavior — if you use a different CNI,
> your pod CIDR will differ and you must adjust `pg_hba.conf`/NetworkPolicy
> references accordingly (see §13.16 Troubleshooting).

---

## 13.2 Prerequisites

**Two machines** (VMs or bare metal), each:
- Ubuntu 22.04 LTS (these steps are Ubuntu/Debian-flavored; adjust package
  manager commands for other distros)
- Minimum 2 vCPUs, 2GB RAM for the control plane; 2 vCPUs, 4GB RAM
  recommended for the worker (it runs the actual app pods)
- Unique hostname per node (`hostnamectl set-hostname k8s-control` /
  `k8s-worker`)
- Full network connectivity between the two (same subnet or routed), and
  outbound internet access to pull packages/images
- `sudo` access
- Swap disabled (kubeadm requires this — steps below)

**On your local workstation** (wherever you'll run `git clone` and, later,
`kubectl` as the cluster admin):
- `git`
- `ssh` access to both nodes

**Unique MAC addresses and product_uuid** — kubeadm requires these to
differ between nodes (an issue with some cloned VM templates):

```bash
# run on both nodes, confirm the values differ
ip link
sudo cat /sys/class/dmi/id/product_uuid
```

---

## 13.3 Step 1 — Clone the repository

On whichever machine you'll manage the cluster from (can be your
workstation, or the control-plane node itself):

```bash
git clone <your-fork-url> full-devsecops-project
cd full-devsecops-project
```

Everything referenced below (`k8s/`, `insurance_app/`, `dashboard/`) is
relative to this checkout.

---

## 13.4 Step 2 — Prepare BOTH nodes (run on control-plane AND worker)

SSH into each node and run this entire section on both before moving on.

**2.1 Disable swap**

```bash
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab   # persist across reboot
```

**2.2 Load required kernel modules**

```bash
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter
```

**2.3 Set required sysctl params (bridged traffic visibility to iptables)**

```bash
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system
```

**2.4 Install containerd (container runtime)**

```bash
sudo apt-get update
sudo apt-get install -y containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

# Use systemd as the cgroup driver — must match kubelet's expectation
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

sudo systemctl restart containerd
sudo systemctl enable containerd
```

**2.5 Install kubeadm, kubelet, kubectl**

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | \
  sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | \
  sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

sudo systemctl enable kubelet
```

(Swap `v1.30` for whatever current stable minor version you want to
standardize on — just use the same version on both nodes.)

**2.6 Open required firewall ports** (skip if both nodes are already on a
trusted private network with no firewall between them; otherwise, per the
official Kubernetes docs):

Control-plane node:
```bash
sudo ufw allow 6443/tcp    # kube-apiserver
sudo ufw allow 2379:2380/tcp  # etcd
sudo ufw allow 10250/tcp   # kubelet API
sudo ufw allow 10259/tcp   # kube-scheduler
sudo ufw allow 10257/tcp   # kube-controller-manager
```

Worker node:
```bash
sudo ufw allow 10250/tcp        # kubelet API
sudo ufw allow 30000:32767/tcp  # NodePort services range
```

Both nodes also need Flannel's overlay traffic (UDP 8472 for VXLAN) open
between them:
```bash
sudo ufw allow 8472/udp
```

---

## 13.5 Step 3 — Initialize the control plane (control-plane node ONLY)

```bash
sudo kubeadm init \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=<CONTROL_PLANE_PRIVATE_IP>
```

This takes a few minutes. On success, kubeadm prints:
1. A `kubeadm join ...` command with a token and hash — **copy this
   somewhere safe**, you'll run it on the worker node in Step 4. Tokens
   expire after 24 hours by default (see Troubleshooting if yours does).
2. Instructions to set up your kubeconfig — run these as the non-root user
   who will run `kubectl`:

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

Verify:
```bash
kubectl get nodes
# NAME             STATUS     ROLES           AGE   VERSION
# k8s-control      NotReady   control-plane   1m    v1.30.x
```

`NotReady` is expected until the CNI is installed (next step).

**Install the Flannel CNI:**

```bash
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
```

Wait ~30-60 seconds, then re-check:

```bash
kubectl get nodes
# k8s-control      Ready      control-plane   3m    v1.30.x
kubectl -n kube-flannel get pods
```

By default the control-plane node is tainted so ordinary workloads won't
schedule on it (correct for a 2-node setup where the worker runs the app).
Leave this taint in place unless you have a specific reason to also run
pods on the control-plane node.

---

## 13.6 Step 4 — Join the worker node

On the **worker node**, run the exact `kubeadm join ...` command that
`kubeadm init` printed in Step 3, e.g.:

```bash
sudo kubeadm join <CONTROL_PLANE_IP>:6443 \
  --token <token> \
  --discovery-token-ca-cert-hash sha256:<hash>
```

If you lost the output or the token expired, generate a new one from the
control-plane node:

```bash
kubeadm token create --print-join-command
```

---

## 13.7 Step 5 — Verify the cluster

Back on the control-plane node (or wherever your kubeconfig points at the
cluster):

```bash
kubectl get nodes -o wide
```

Expected:
```
NAME          STATUS   ROLES           AGE     VERSION
k8s-control   Ready    control-plane   10m     v1.30.x
k8s-worker    Ready    <none>          2m      v1.30.x
```

Both `Ready` means you have a working 2-node cluster. Confirm system pods
are healthy:

```bash
kubectl get pods -A
```

Everything in `kube-system` and `kube-flannel` should be `Running`.

---

## 13.8 Step 6 — Install the ingress-nginx controller

The project's `k8s/ingress.yaml` uses `ingressClassName: nginx` plus
ModSecirity/OWASP-CRS annotations, which the standard `ingress-nginx`
project's controller image supports:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  -n ingress-nginx --create-namespace
```

Since you have no cloud load balancer on a bare-metal 2-node cluster, the
Service is created as `LoadBalancer` type by default but will stay
`<pending>` for `EXTERNAL-IP` unless you also install something like
MetalLB. For a straightforward setup, patch it to `NodePort` instead so
you can reach it via the worker node's IP:

```bash
kubectl -n ingress-nginx patch svc ingress-nginx-controller \
  -p '{"spec": {"type": "NodePort"}}'
kubectl -n ingress-nginx get svc ingress-nginx-controller
# note the NodePort mapped to 80/443, e.g. 30080/30443
```

Point `insurance.local` at the **worker node's** IP (that's where ingress
traffic actually lands with NodePort):

```bash
echo "<WORKER_NODE_IP> insurance.local" | sudo tee -a /etc/hosts
```

If you access the app via a specific NodePort rather than plain
`http://insurance.local` (i.e. port 80/443 aren't otherwise proxied to the
NodePort), use `http://insurance.local:<nodeport>` accordingly.

---

## 13.9 Step 7 — Shared infrastructure: NFS server + PostgreSQL

These can live on either node, a third VM, or — for a minimal 2-node
setup — the **control-plane node** (it has spare capacity since it doesn't
run app pods). All commands below assume you're putting both there;
adjust the IP references throughout the rest of this guide if you place
them elsewhere.

```bash
# On the control-plane node:
sudo apt install -y nfs-kernel-server postgresql

sudo mkdir -p /srv/nfs/scan-input /srv/nfs/scan-input-2
echo "/srv/nfs/scan-input <WORKER_NODE_IP>/32(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
echo "/srv/nfs/scan-input-2 <WORKER_NODE_IP>/32(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -ra
sudo systemctl restart nfs-kernel-server
```

**Important**: with Flannel, pods get IPs from the **pod network**
(`10.244.0.0/16`), not the node's own IP — so the NFS export and
`pg_hba.conf` rules below must allow the **pod CIDR**, not just the
worker node's own IP:

```bash
# broaden the NFS export to the whole pod network too
echo "/srv/nfs/scan-input 10.244.0.0/16(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
echo "/srv/nfs/scan-input-2 10.244.0.0/16(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -ra
```

PostgreSQL — create the two databases (see
[06-security-reporting-api.md](06-security-reporting-api.md) §6.2 and
[09-av-yara-scanner.md](09-av-yara-scanner.md) for schemas):

```bash
sudo -u postgres psql <<'SQL'
CREATE DATABASE security_reports;
CREATE USER security_api WITH PASSWORD 'change_me';
GRANT ALL PRIVILEGES ON DATABASE security_reports TO security_api;

CREATE DATABASE av_scanner;
CREATE USER av_scanner_user WITH PASSWORD 'change_me_too';
GRANT ALL PRIVILEGES ON DATABASE av_scanner TO av_scanner_user;
SQL
```

Allow the pod network to reach Postgres — edit `pg_hba.conf` (find its
path with `sudo -u postgres psql -c "SHOW hba_file;"`):

```
# add near the top, before the more restrictive default rules:
host    all             all             10.244.0.0/16           md5
```

And make sure Postgres listens beyond localhost (`postgresql.conf`:
`listen_addresses = '*'`), then:

```bash
sudo systemctl restart postgresql
```

Load the schemas:

```bash
cd full-devsecops-project
psql -h localhost -U security_api -d security_reports -f dashboard/schema.sql
# (create the deployments/security_scans/security_findings tables first —
#  see docs/06-security-reporting-api.md §6.2 for the exact CREATE TABLE statements)
psql -h localhost -U av_scanner_user -d av_scanner -f k8s/av/sql/schema.sql
```

---

## 13.10 Step 8 — Namespace and secrets

```bash
kubectl create namespace devsecops

kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<your-github-username> \
  --docker-password=<your-github-PAT-with-read:packages> \
  -n devsecops

kubectl create secret generic mysql-credentials \
  --from-literal=DB_USER=insurance_user \
  --from-literal=DB_PASSWORD='change_me_app' \
  --from-literal=DB_NAME=insurance \
  -n devsecops

kubectl create secret generic smtp-credentials \
  --from-literal=SMTP_USER=your-mailbox@gmail.com \
  --from-literal=SMTP_PASSWORD='your-app-password' \
  -n devsecops

kubectl create secret generic backend-jwt-secret \
  --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
  -n devsecops
```

---

## 13.11 Step 9 — Deploy the application

Edit `k8s/backend/app-nfs-storage.yaml` so both `nfs.server:` fields point
at the control-plane node's IP (or wherever you put the NFS server in
Step 7), then:

```bash
kubectl apply -f k8s/backend/app-nfs-storage.yaml
kubectl apply -f k8s/mysql/deployment.yaml -f k8s/mysql/service.yaml
kubectl apply -f k8s/backend/deployment.yaml -f k8s/backend/service.yaml
kubectl apply -f k8s/frontend/deployment.yaml -f k8s/frontend/service.yaml
kubectl apply -f k8s/ingress.yaml
```

Before applying, bump the image tags in `k8s/backend/deployment.yaml` /
`k8s/frontend/deployment.yaml` to a tag that actually exists in **your**
GHCR (the checked-in tags are the original author's build SHAs) — see
[08-kubernetes-deployment.md](08-kubernetes-deployment.md) §8.8 for the
one-liner `sed` commands, or push through your own CI first
([05-cicd-pipeline.md](05-cicd-pipeline.md)).

Watch it come up — pods should land on the **worker** node:

```bash
kubectl -n devsecops get pods -o wide -w
```

Visit `http://insurance.local` (or `http://insurance.local:<nodeport>` if
you used the NodePort patch in Step 6).

---

## 13.12 Step 10 — Deploy the AV/YARA scanner

Build the watcher image somewhere it can be pushed to a registry your
cluster can pull from (a real `kubeadm` cluster, unlike minikube, has no
"share the host's Docker daemon" shortcut):

```bash
docker build -f k8s/av/Dockerfile.watcher -t ghcr.io/<your-namespace>/av-watcher:latest k8s/av/
docker push ghcr.io/<your-namespace>/av-watcher:latest
```

Edit `k8s/av/manifests/30-deployment.yaml` to reference that pushed image
(rather than a local-only tag) and set `imagePullPolicy: Always` or
`IfNotPresent`. Edit `k8s/av/manifests/10-storage.yaml` (NFS IP) and
`k8s/av/manifests/25-secret.yaml` (Postgres credentials pointing at the
control-plane node's IP/postgres you set up in Step 7), then:

```bash
kubectl apply -f k8s/av/manifests/00-namespace.yaml
kubectl apply -f k8s/av/manifests/10-storage.yaml
kubectl apply -f k8s/av/manifests/20-configmaps.yaml
kubectl apply -f k8s/av/manifests/25-secret.yaml
kubectl apply -f k8s/av/manifests/30-deployment.yaml
kubectl apply -f k8s/av/manifests/40-networkpolicy.yaml

kubectl -n av-scanning get pods -w
```

Full detail: [09-av-yara-scanner.md](09-av-yara-scanner.md).

---

## 13.13 Step 11 — Monitoring stack

```bash
kubectl create namespace monitoring
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring -f k8s/values.yaml
helm install loki grafana/loki -n monitoring -f k8s/loki-values.yaml
helm install promtail grafana/promtail -n monitoring -f k8s/promtail-values.yaml
```

As covered in [10-monitoring-logging.md](10-monitoring-logging.md), this
watches the app's own pods (backend/frontend/mysql/av-scanner), not the
cluster's control-plane internals — that's intentional.

---

## 13.14 Step 12 — CI/CD, security-api, and the Aegis dashboard

These don't run *inside* the 2-node cluster in this project's design —
`security-api` and `dashboard` run on a host with `kubectl` access to it
(this can be the control-plane node, since it's not running app pods and
already has spare capacity, or your own workstation if it can reach the
cluster and Postgres).

Follow, in order:
1. [05-cicd-pipeline.md](05-cicd-pipeline.md) — wire up GitHub Actions
2. [06-security-reporting-api.md](06-security-reporting-api.md) — run
   `security-api`, expose it (ngrok or a self-hosted runner) so CI can
   reach it
3. [07-aegis-dashboard.md](07-aegis-dashboard.md) — run the Streamlit
   dashboard, pointed at the same Postgres and at this cluster's
   `kubectl` context

---

## 13.15 Step 13 — Full verification

```bash
kubectl get nodes                      # 2 nodes, both Ready
kubectl -n devsecops get pods           # backend, frontend, mysql Running
kubectl -n av-scanning get pods         # av-scanner Running (3/3 containers)
kubectl -n monitoring get pods          # prometheus, loki, promtail Running
kubectl -n ingress-nginx get pods       # ingress controller Running
```

Then run through Phase 11 of
[11-full-deployment-walkthrough.md](11-full-deployment-walkthrough.md)
(push a code change, watch CI, triage in Aegis, deploy, submit a test
claim, confirm the AV scan) to prove the whole loop works end-to-end on
your real cluster.

---

## 13.16 Troubleshooting

### Cluster bootstrap (`kubeadm init` / `kubeadm join`)

| Symptom | Cause | Fix |
|---|---|---|
| `kubeadm init` fails at preflight checks: "swap is enabled" | Swap not (fully) disabled | Re-run `sudo swapoff -a`; confirm `/etc/fstab` swap line is commented; reboot if it still shows as active (`free -h`) |
| Preflight error: "Port 6443 is in use" / "10250 in use" | A previous failed `kubeadm init` left state behind | `sudo kubeadm reset` then retry; also `sudo rm -rf /etc/cni/net.d /var/lib/etcd` on the control-plane node if resetting doesn't fully clear it |
| `kubeadm join` fails: "token has expired" | Default token TTL is 24h | On the control-plane node: `kubeadm token create --print-join-command` and use the fresh output |
| `kubeadm join` fails: "context deadline exceeded" reaching `<IP>:6443` | Firewall blocking 6443 between nodes, or wrong `--apiserver-advertise-address` | Confirm `sudo ufw status`/security groups allow 6443 from the worker's IP; `telnet <control-plane-ip> 6443` from the worker to test connectivity directly |
| Both nodes show the same `product_uuid` / MAC address | Cloned from the same VM template without regenerating machine-id | `sudo cat /sys/class/dmi/id/product_uuid` must differ; regenerate with your hypervisor's tooling, or rebuild one node from a fresh image |
| `kubectl get nodes` shows `NotReady` after join, indefinitely | CNI not installed, or CNI pods not scheduling | `kubectl get pods -n kube-flannel`; if pending/crashlooping, check `kubectl describe pod` for the reason (commonly: node's kernel modules from §13.4.2 missing — re-run those steps) |

### Cgroup driver mismatches

| Symptom | Cause | Fix |
|---|---|---|
| kubelet fails to start / `CrashLoopBackOff`-like restarts at the systemd level, logs mention cgroup driver mismatch | containerd and kubelet must agree on `systemd` as the cgroup driver | Confirm `/etc/containerd/config.toml` has `SystemdCgroup = true` (§13.4.4); `sudo systemctl restart containerd kubelet` after fixing |

### Networking (Flannel / pod CIDR)

| Symptom | Cause | Fix |
|---|---|---|
| Pods stuck `ContainerCreating`, events show CNI errors | Flannel not installed yet, or installed with a mismatched `--pod-network-cidr` | Confirm you passed `--pod-network-cidr=10.244.0.0/16` to `kubeadm init` — Flannel's default manifest expects exactly that range unless you edit its ConfigMap too |
| Pods on different nodes can't reach each other | VXLAN (UDP 8472) blocked between nodes | Open `8472/udp` on both nodes' firewalls (§13.4.6) |
| AV watcher can't write to Postgres, no errors visible in watcher logs | `pg_hba.conf` allows the wrong subnet (node IP instead of pod CIDR) — this is a real issue documented in `k8s/av/readme.md` §8, problem 7 | Confirm the pod's actual IP with `kubectl get pod <name> -o wide -n av-scanning`; make sure `pg_hba.conf` has an entry for `10.244.0.0/16` (or your actual pod CIDR), not just the worker node's IP |

### Ingress / access

| Symptom | Cause | Fix |
|---|---|---|
| `curl http://insurance.local` times out | `/etc/hosts` points at the wrong IP, or the ingress Service is still `LoadBalancer` type with `<pending>` external IP | Patch the Service to `NodePort` (§13.8) and point `/etc/hosts` at the **worker node's** IP with the right port |
| Ingress returns 404 for everything | `ingressClassName: nginx` doesn't match your installed controller's class name | `kubectl get ingressclass` to confirm the exact name; align `k8s/ingress.yaml` if your Helm install used a different release name/class |
| ModSecurity annotations seem to have no effect | Standard `ingress-nginx` builds do include ModSecurity support, but some minimal/custom builds strip it | `kubectl -n ingress-nginx logs deploy/ingress-nginx-controller \| grep -i modsecurity` to confirm the module loaded |

### Image pulls

| Symptom | Cause | Fix |
|---|---|---|
| Worker node pods `ImagePullBackOff` for `ghcr.io/...` images | `ghcr-secret` missing/wrong, package private and PAT lacks `read:packages`, or the tag genuinely doesn't exist yet in your GHCR | `kubectl describe pod <pod> -n devsecops` for the exact registry error; regenerate the PAT with the right scope; confirm via `docker pull ghcr.io/<you>/backend:<tag>` from your own machine first |
| AV watcher image `ImagePullBackOff` | You built it locally without pushing anywhere reachable by the worker node — unlike minikube, a real 2-node cluster has no shared local Docker daemon shortcut | Push the image to GHCR (or any registry your cluster can reach) and reference the full path, as shown in §13.12 |

### General diagnostic commands worth knowing

```bash
kubectl get events -A --sort-by=.lastTimestamp   # cluster-wide recent events, newest last
kubectl describe node <node-name>                 # capacity, conditions, taints
journalctl -u kubelet -f                           # kubelet logs on that node
journalctl -u containerd -f                        # container runtime logs on that node
kubectl -n kube-system get pods                    # core control-plane component health
```
