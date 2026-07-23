# 9. AV/YARA File Scanner (`k8s/av/`)

This sub-system scans every file the backend writes to the shared NFS
`scan-input` volume (i.e. every insurance claim attachment) with ClamAV
and YARA, and routes it based on the verdict.

> The repo already ships a very thorough `k8s/av/readme.md` written
> file-by-file with a full "problems faced" debugging log. This document
> summarizes it for the overall project narrative and points you to it for
> full detail — **read `k8s/av/readme.md` directly for anything not
> covered below**, especially Section 8 (problems faced) and Section 9
> (known gaps before production), which are worth reading in full before
> you deploy this in anything beyond a demo.

## 9.1 What it is, in one paragraph

One Kubernetes Deployment (namespace `av-scanning`) running **one pod with
three containers** — `clamd` (the ClamAV daemon), `freshclam` (keeps the
virus signature DB updated), and `watcher` (a polling loop that scans every
stable file with both ClamAV and YARA, then moves it to a clean-output
share, or deletes it and logs the verdict if flagged). It's built and
tested against minikube (docker driver) + an NFS server + PostgreSQL all
on the same host VM.

## 9.2 Why polling instead of `inotify`

This is the single most important design decision to understand: `inotify`
does **not** propagate across NFS for writes made by other clients — a
fundamental kernel limitation, not a bug to fix. The watcher instead
`find`s the scan directory every `POLL_INTERVAL_SECONDS` (default 5s) and
only scans a file once its size is unchanged across two consecutive polls
(so it doesn't scan a half-written upload). This means detection latency
is roughly `2 × POLL_INTERVAL_SECONDS`, not near-instant.

## 9.3 Routing logic

| Verdict | Action | Postgres row written? |
|---|---|---|
| `CLEAN` | Moved to `clean-output` | Yes, `overall_status='CLEAN'`, always |
| `FLAGGED` (ClamAV signature or YARA rule match) | Deleted from `scan-input` | Yes, **before** deletion — file path, matched signature/rule, and raw tool output are preserved even though the file is gone |
| `ERROR` | Deleted from `scan-input` | Yes, `overall_status='ERROR'` |

There is currently no quarantine step — flagged/errored files are deleted
outright with no recovery path if a detection turns out to be a false
positive. See `k8s/av/readme.md` Section 9, gap #6, if you need that
safety net.

## 9.4 Deployment runbook (condensed — see `k8s/av/readme.md` §6 for full detail)

```bash
# 1. Schema first
psql -h <PG_HOST> -U <PG_USER> -d av_scanner -f k8s/av/sql/schema.sql

# 2. Build the watcher image
eval $(minikube docker-env)          # only if using minikube+docker driver
docker build -f k8s/av/Dockerfile.watcher -t av-watcher:latest k8s/av/

# 3. Edit before applying:
#    - k8s/av/manifests/10-storage.yaml    -> real NFS server IP (both PVs)
#    - k8s/av/manifests/25-secret.yaml     -> real Postgres credentials
#    - k8s/av/manifests/20-configmaps.yaml -> real YARA rules (replace starter.yar)
#    - k8s/av/manifests/30-deployment.yaml -> real image ref for non-minikube clusters

# 4. Apply in order
kubectl apply -f k8s/av/manifests/00-namespace.yaml
kubectl apply -f k8s/av/manifests/10-storage.yaml
kubectl apply -f k8s/av/manifests/20-configmaps.yaml
kubectl apply -f k8s/av/manifests/25-secret.yaml
kubectl apply -f k8s/av/manifests/30-deployment.yaml
kubectl apply -f k8s/av/manifests/40-networkpolicy.yaml

# 5. Verify
kubectl -n av-scanning get pods -w
kubectl -n av-scanning logs deploy/av-scanner -c watcher -f

# 6. Test with EICAR (harmless AV test string — should be deleted + logged FLAGGED)
curl -s https://secure.eicar.org/eicar.com.txt -o /path/to/scan-input/eicar-test.txt

# 7. Test clean pass-through (should move to clean-output, logged CLEAN)
echo "hello" > /path/to/scan-input/clean-test.txt
```

## 9.5 Important production gaps to close before real use

Pulled directly from the repo's own gap analysis — do not skip this list:

1. **Image distribution**: `imagePullPolicy: Never` + `minikube docker-env`
   only works locally. Push to a real registry for anything beyond a
   single-node demo, and pin a digest/tag rather than `latest`.
2. **Secrets**: `manifests/25-secret.yaml` ships with placeholder values —
   never commit real Postgres credentials to it; use `kubectl create
   secret generic` imperatively or a real secrets manager.
3. **NFS is a single VM** — no redundancy, single point of failure.
4. **PostgreSQL is unmanaged/unbacked-up** — move to a managed service or
   add backups; add PgBouncer if scan volume grows (the watcher opens a
   new connection per file).
5. **Cannot horizontally scale as-is** — two replicas would double-scan
   every file. Scaling needs a work-queue redesign (Redis/RabbitMQ/SQS +
   a separate worker pool), not more replicas of the current watcher.
6. **No quarantine/recovery for false positives** — flagged/errored files
   are deleted permanently.
7. **YARA ruleset is a placeholder** (`starter.yar`) — replace with a
   maintained ruleset (e.g. YARA-Forge, Neo23x0/signature-base) before
   production; large rulesets may need a git-sync init container instead
   of a ConfigMap (ConfigMaps cap out around 1MB).
8. **freshclam egress is `0.0.0.0/0` on 80/443** in the NetworkPolicy —
   tighten to ClamAV's actual mirror CIDR ranges.
9. **Polling interval is a latency/load tradeoff** — tune
   `POLL_INTERVAL_SECONDS` against your NFS server's tolerance for
   constant `find` traversals.
10. **Resource limits (1Gi/2Gi for `clamd`)** were sized for a quick POC —
    the signature DB grows over time; monitor for OOMKills after DB updates.
11. **Observability is `kubectl logs` + direct SQL only** today — ship
    logs centrally (this project's Loki/Promtail stack — see
    [10-monitoring-logging.md](10-monitoring-logging.md) — is a natural
    fit), alert automatically on `FLAGGED`/`ERROR` rows, and add a
    liveness/readiness probe on the `watcher` container itself (currently
    only `clamd` has one).

## 9.6 Querying results directly

```sql
-- All flagged files, most recent first
SELECT scanned_at, file_name, file_path, clamav_status, yara_status
FROM scan_results
WHERE overall_status = 'FLAGGED'
ORDER BY scanned_at DESC;

-- Daily scan volume / detection rate
SELECT date_trunc('day', scanned_at) AS day,
       count(*) AS total,
       count(*) FILTER (WHERE overall_status = 'FLAGGED') AS flagged,
       count(*) FILTER (WHERE overall_status = 'ERROR') AS errors
FROM scan_results
GROUP BY 1
ORDER BY 1 DESC;
```

Or view the same data in the Aegis dashboard's **AV Results** tab (read-only,
last 500 rows).
