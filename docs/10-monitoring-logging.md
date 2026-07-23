# 10. Monitoring & Logging Stack

The repo includes Helm values files for three pieces of the standard
Kubernetes observability stack. These are **values files only** — you
supply the Helm charts and repos yourself; nothing in `k8s/` templates or
auto-installs them.

## 10.1 Scope: this stack watches the application, not the cluster's internals

This is a deliberate design choice, not a partial setup: `k8s/values.yaml`
explicitly disables scraping of `kubeEtcd`, `kubeControllerManager`, and
`kubeScheduler`. Those three are the Kubernetes **control plane's own**
internals — this project has no reason to monitor them, because the goal
here is observability for the **insurance app and its supporting
services** (backend, frontend, MySQL, the AV scanner), not for the
cluster's control plane. Disabling them isn't a limitation of a managed
cluster you can't reach; it's the correct, intentional scope for what this
stack is for.

In short: Prometheus scrapes your workloads' pods/services (backend,
frontend, mysql, av-scanner) and Loki/Promtail collect their logs. That is
the stack doing exactly what it's there to do for this project — app-level
monitoring and logging, not general cluster-infrastructure monitoring.

## 10.2 What's included

| File | For chart | What it configures |
|---|---|---|
| `k8s/values.yaml` | `kube-prometheus-stack` (Prometheus Community) | Scopes Prometheus to application/workload monitoring: disables Alertmanager and Grafana (`enabled: false` for both — bring your own or enable later once you've decided what to alert on/visualize), sets Prometheus retention to 3 days, and disables `kubeEtcd`/`kubeControllerManager`/`kubeScheduler` scraping since this stack isn't for observing the control plane |
| `k8s/loki-values.yaml` | `loki` (Grafana) | `SingleBinary` deployment mode (all-in-one, not the microservices split), filesystem storage (no object store like S3/GCS configured), replication factor 1, all the microservices-mode replica counts (`ingester`, `distributor`, `querier`, etc.) zeroed out since they're unused in single-binary mode, `gateway`/`chunksCache`/`resultsCache` disabled |
| `k8s/promtail-values.yaml` | `promtail` (Grafana) | Points Promtail's log shipping client at `http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push` so every app pod's stdout/stderr (backend, frontend, mysql, av-scanner) ends up queryable in Loki |
| `k8s/get_helm.sh` | — | The official upstream Helm install script, vendored into the repo so you don't need internet access to a different domain to bootstrap Helm itself |

## 10.3 Installing Helm (if you don't already have it)

```bash
chmod +x k8s/get_helm.sh
./k8s/get_helm.sh
helm version
```

(Or use your OS package manager / the official instructions at
https://helm.sh/docs/intro/install/ — the vendored script is just a
convenience.)

## 10.4 Installing the stack

```bash
kubectl create namespace monitoring

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Prometheus (Alertmanager + Grafana disabled per values.yaml)
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  -n monitoring -f k8s/values.yaml

# Loki (single-binary mode, filesystem storage)
helm install loki grafana/loki -n monitoring -f k8s/loki-values.yaml

# Promtail (ships pod logs to Loki)
helm install promtail grafana/promtail -n monitoring -f k8s/promtail-values.yaml
```

## 10.5 What you get, and how to view it

- **Metrics for the app**: Prometheus scrapes the `devsecops` and
  `av-scanning` namespaces' pods/services (backend, frontend, mysql,
  av-scanner) — not the control plane, per the scoping in 10.1 — with
  3-day retention. There is no Grafana instance in this configuration to
  visualize them yet — either flip `grafana.enabled: true` in
  `k8s/values.yaml` and re-run the `helm upgrade`, or install Grafana
  separately and point it at this Prometheus
  (`http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090`).
- **Logs for the app**: Promtail ships every app pod's stdout/stderr to
  Loki — the backend's request logs, the frontend's nginx access logs, the
  AV watcher's scan decisions, MySQL's own log output. Query them either
  via `logcli`, Grafana's Explore view (once you have Grafana pointed at
  `http://loki.monitoring.svc.cluster.local:3100`), or `kubectl logs`
  directly for anything recent.
- **Alerting**: Alertmanager is disabled by default so that alerting rules
  get defined deliberately for this app's actual failure modes, rather
  than inheriting generic cluster-wide defaults. If you act on the AV
  scanner's gap #11 recommendation (alert on `FLAGGED`/`ERROR` rows), this
  is the natural place to wire that up (e.g. a Prometheus recording
  rule/exporter reading the `scan_results` table, or a simple scheduled
  job that queries Postgres and pushes to Alertmanager/a webhook).

## 10.6 Verifying

```bash
kubectl -n monitoring get pods
kubectl -n monitoring get svc

# port-forward Prometheus to check it's scraping
kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090:9090
# then open http://localhost:9090/targets
```

## 10.7 Recap: why the setup looks "minimal"

This stack doesn't ship pre-built dashboards, alert rules, or a wired-up
Grafana — and that's consistent with its purpose, not a shortfall. It
exists to monitor and log **this application's** components (backend,
frontend, MySQL, AV scanner), and it does that correctly by collecting
their metrics and logs while staying out of the Kubernetes control plane's
business. The collection layer (Prometheus + Loki + Promtail) is complete
and doing its job; dashboards and alert rules are the next layer to add,
tailored to what actually matters for this app (claim submission error
rates, AV scan backlog, security-findings ingestion failures, etc.) rather
than generic defaults.
