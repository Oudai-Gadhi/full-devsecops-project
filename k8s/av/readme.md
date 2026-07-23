# AV/YARA NFS Scanner — Technical Documentation

## 1. Purpose

This system automatically scans files dropped onto a shared NFS volume using
**ClamAV** (signature-based AV) and **YARA** (custom rule-based detection),
records the verdict for every file in **PostgreSQL**, and routes files based
on outcome:

- **Clean files** are moved automatically to a second NFS share that admins
  view directly.
- **Flagged files** (ClamAV or YARA detection) are **deleted** from the
  input share. The original file path, detection details (signature/rule
  matched), and full raw tool output are recorded in Postgres before
  deletion, so there's a complete audit trail even though the file itself
  is gone.
- **Errored files** only stay in the first NFS

---

## 2. Repository layout

This matches the actual folder structure under `~/k8s/av`:

```
av/
|-- clamd_scan.py            # raw clamd INSTREAM protocol client (Python, no clamdscan dependency)
|-- Dockerfile.watcher        # builds the watcher container image
|-- watcher.sh                 # polling loop + scan orchestration + Postgres writer
|-- readme.md                  # this file
|-- starter.yar                 # placeholder YARA rules (replace before prod)
|-- manifests/
|   |-- 00-namespace.yaml      # av-scanning namespace
|   |-- 10-storage.yaml        # PVCs: clamav-db, scan-input-nfs, clean-output-nfs
|   |-- 20-configmaps.yaml     # yara-rules ConfigMap, clamd-conf ConfigMap
|   |-- 25-secret.yaml         # Postgres credentials (template - do not commit real values)
|   |-- 30-deployment.yaml     # the av-scanner Deployment (clamd+freshclam+watcher)
|   `-- 40-networkpolicy.yaml  # egress rules for the scanner pod
`-- sql/
    `-- schema.sql              # scan_results table definition
```

---

## 3. Architecture overview

```
                         +-------------------------------------------+
                         |   NFS Server (external VM/NAS)            |
                         |   /srv/nfs/scan-input    (drop zone)      |
                         |   /srv/nfs/scan-input-2  (clean output)   |
                         +--------------------+------------------------+
                                              | NFS mounts (RWX)
                  +---------------------------+-------------------------+
                  |  Kubernetes namespace: av-scanning                  |
                  |                                                     |
                  |  Deployment: av-scanner (1 pod, 3 containers)       |
                  |  +-----------+   +-----------+   +---------------+  |
                  |  |   clamd   |   | freshclam |   |    watcher    |  |
                  |  | (daemon,  |   | (updates  |   | (polling loop |  |
                  |  |  :3310)   |   |  virus DB)|   |  + scan logic)|  |
                  |  +-----+-----+   +-----+-----+   +-------+-------+  |
                  |        |  shared PVC    |                |         |
                  |        +----------------+                |         |
                  |                                          |          |
                  +------------------------------------------+----------+
                                                               |
                                                       INSERT scan_results
                                                               |
                                                    +----------v-----------+
                                                    |   PostgreSQL (VM)    |
                                                    |   av_scanner DB      |
                                                    +-----------------------+
```

**Why one pod, three containers:** `clamd` and `watcher` talk over
`localhost`, and all three need the same NFS/PVC mounts. Co-locating them
in one pod keeps networking trivial and guarantees they're always
scheduled together. Tradeoff: cannot be horizontally scaled as-is (see
Section 9).

**Why `Recreate` strategy + 1 replica:** two pods both polling the same NFS
share would double-scan every file and double-insert into Postgres.

---

## 4. File-by-file reference

### `clamd_scan.py`
A ~40-line Python script that speaks clamd's native `INSTREAM` protocol
directly over a plain TCP socket: sends `zINSTREAM\0`, streams the file in
length-prefixed chunks, sends a zero-length terminator, reads back the
verdict line (`OK` or `<signature> FOUND`). Exit codes: `0` = clean,
`1` = infected, `2` = error. Also used for the `clamd` readiness check via
a `zPING\0` / `PONG` exchange. This deliberately replaces the `clamdscan`
CLI tool entirely - see Section 8, Problem 8.

### `Dockerfile.watcher`
Debian-slim base image with `yara`, `python3` (runs `clamd_scan.py`), and
`postgresql-client` installed. No `clamav-daemon`/`clamdscan` dependency.
Entrypoint is `watcher.sh`.

### `watcher.sh`
The core orchestration logic, in order:
1. Wait for `clamd` to respond to a `PING` (via `clamd_scan.py`'s ping
   function) before entering the main loop.
2. Run a polling loop: every `POLL_INTERVAL_SECONDS` (default 5s), `find`
   all files under `$SCAN_DIR`. A file is only scanned once its size is
   unchanged across two consecutive polls (so partially-written files are
   skipped until they're stable). Polling is used instead of `inotify`
   deliberately - see Section 8, Problem 7.
3. For each stable file, scan it via `clamd_scan.py` (ClamAV), then run
   `yara -r` against the same file.
4. Compute an overall verdict: `CLEAN` / `FLAGGED` / `ERROR`.
5. Route by verdict:
   - `CLEAN` -> `mv` to `$CLEAN_DIR`
   - `FLAGGED` -> `rm -f` from `$SCAN_DIR`
   - `ERROR` -> `rm -f` from `$SCAN_DIR`
   (all three cases result in the file leaving `$SCAN_DIR` one way or
   another - see Section 8, Problem 9 for the ERROR-deletion tradeoff)
6. Insert one row into `scan_results` in Postgres - always, regardless of
   outcome, and always *before* deletion for flagged/errored files, so the
   record (original path, signatures/rules matched, raw tool output)
   survives even though the file doesn't.

Configuration is entirely via environment variables: `SCAN_DIR`,
`CLEAN_DIR`, `YARA_RULES`, `POLL_INTERVAL_SECONDS`, `CLAMD_SOCKET_HOST`,
`CLAMD_SOCKET_PORT`, `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`,
`PGPASSWORD`.

### `starter.yar`
Three placeholder rules: double-extension detection, suspicious PowerShell
encoded-command strings, and an EICAR test-string rule (useful for
verifying the whole pipeline works without needing real malware). Replace
with a maintained ruleset before production.

### `sql/schema.sql`
One table, `scan_results` - one row per scanned file, written regardless of
outcome:

| Column | Purpose |
|---|---|
| `file_path`, `file_name`, `file_size_bytes`, `sha256` | File identity, captured even after deletion |
| `clamav_status`, `clamav_signature` | ClamAV verdict + matched signature name |
| `yara_status`, `yara_matches` | YARA verdict + matched rule names (array) |
| `overall_status` | `CLEAN` / `FLAGGED` / `ERROR` |
| `raw_clamav_output`, `raw_yara_output` | Full tool output, useful for debugging false positives |
| `host_node`, `pod_name` | Which node/pod performed the scan |

### `manifests/00-namespace.yaml`
Creates the `av-scanning` namespace.

### `manifests/10-storage.yaml`
Three PVCs:
- **`clamav-db`** - `ReadWriteOnce`, default StorageClass. Holds ClamAV's
  signature DB so it survives pod restarts without a full re-download.
- **`scan-input-nfs`** - `ReadWriteMany`, PV/PVC pair pointing at
  `<NFS_SERVER_IP>:/srv/nfs/scan-input`. The drop zone.
- **`clean-output-nfs`** - same pattern, `<NFS_SERVER_IP>:/srv/nfs/scan-input-2`.

**Edit the `server:` field** (`CHANGE_ME_NFS_SERVER_IP`) on both
`PersistentVolume` definitions before applying.

### `manifests/20-configmaps.yaml`
Two ConfigMaps:
- **`yara-rules`** - contains `starter.yar`, mounted at `/rules` in the
  watcher container.
- **`clamd-conf`** - contains `clamd.conf` and `freshclam.conf`, mounted
  individually via `subPath` into the `clamd`/`freshclam` containers only
  (the watcher no longer needs these at all - see Section 8, Problem 8).

### `manifests/25-secret.yaml`
Template for Postgres credentials (`PGHOST`, `PGPORT`, `PGDATABASE`,
`PGUSER`, `PGPASSWORD`). **Contains placeholder values - never apply as-is
in production.**

### `manifests/30-deployment.yaml`
The core workload: one init container, three long-running containers.

| Container | Role | Notes |
|---|---|---|
| `freshclam-init` (init) | Pulls an initial virus DB before `clamd` starts | Prevents `clamd` crashing on a totally empty DB volume on first boot |
| `clamd` | ClamAV daemon | TCP port 3310; PID file on a dedicated `emptyDir` volume |
| `freshclam` | Keeps virus DB updated | Runs as `-d --foreground` |
| `watcher` | Scanning orchestration | Built from `watcher.sh` + `clamd_scan.py`; only mounts NFS shares + YARA rules - no clamd config needed |

Volumes:
- `clamav-db` (PVC) -> `/var/lib/clamav`
- `clamd-conf` (ConfigMap, subPath) -> individual conf files, `clamd`/`freshclam` only
- `scan-input` (PVC) -> `/scan-input`
- `clean-output` (PVC) -> `/clean-output`
- `yara-rules` (ConfigMap) -> `/rules`
- `clamd-run` (emptyDir) -> `/var/run/clamav`, `clamd` only

### `manifests/40-networkpolicy.yaml`
Restricts egress to: DNS, Postgres (5432), HTTP/HTTPS (80/443) for
freshclam updates. The HTTP(S) rule is currently `0.0.0.0/0` - tighten in
production (Section 9).

---

## 5. Environment

Built and tested against:
- **Kubernetes**: minikube, **docker driver** (the "node" is a container on
  the host, not a VM)
- **NFS server**: `nfs-kernel-server` on the same Ubuntu host VM as
  minikube
- **PostgreSQL**: also on the same host VM

---

## 6. Deployment runbook

```bash
# 0. Prerequisites: NFS server exporting both shares, Postgres reachable,
#    schema loaded:
psql -h <PG_HOST> -U <PG_USER> -d av_scanner -f sql/schema.sql

# 1. Build the watcher image (minikube + docker driver):
eval $(minikube docker-env)
docker build -f Dockerfile.watcher -t av-watcher:latest .

# 2. Edit before applying:
#    - manifests/10-storage.yaml    -> real NFS server IP (both PVs)
#    - manifests/25-secret.yaml     -> real Postgres credentials
#    - manifests/20-configmaps.yaml -> real YARA rules
#    - manifests/30-deployment.yaml -> real image ref + imagePullPolicy (prod only)

# 3. Apply in order
kubectl apply -f manifests/00-namespace.yaml
kubectl apply -f manifests/10-storage.yaml
kubectl apply -f manifests/20-configmaps.yaml
kubectl apply -f manifests/25-secret.yaml
kubectl apply -f manifests/30-deployment.yaml
kubectl apply -f manifests/40-networkpolicy.yaml

# 4. Verify
kubectl -n av-scanning get pods -w
kubectl -n av-scanning logs deploy/av-scanner -c watcher -f

# 5. Test - EICAR (should be DELETED from scan-input; FLAGGED row in DB)
curl -s https://secure.eicar.org/eicar.com.txt -o /path/to/scan-input/eicar-test.txt

# 6. Test - clean pass-through (should move to clean-output; CLEAN row in DB)
echo "hello" > /path/to/scan-input/clean-test.txt
```

## 7. Querying results

```sql
-- All flagged files, most recent first (file itself no longer exists, but
-- the record does)
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

---

## 8. Problems faced (chronological, build/debug log)

1. **Wrong ClamAV image tag.** `clamav/clamav:1.3` doesn't exist on Docker
   Hub - switched to the `stable` tag.

2. **ClamAV's bundled certs hidden.** Mounting the `clamd-conf` ConfigMap at
   `/etc/clamav` as a whole directory replaced the entire directory inside
   the image, hiding the bundled cert files ClamAV needs for signature
   verification (`Invalid certs directory '/etc/clamav/certs/'`). Fixed by
   mounting each config file individually via `subPath`, to a different
   path that doesn't collide with anything the image ships.

3. **`clamd` log file symlink loop.** Setting `LogFile /dev/stdout` (or
   `UpdateLogFile` for freshclam) caused `Failed to open log file
   /dev/stdout: Symbolic link loop` under this container runtime. Fixed by
   removing those directives and running with `--foreground` /
   `--stdout` flags instead.

4. **`clamd` couldn't write its PID file.** `/var/run/clamav/` normally
   gets created by the image's own entrypoint script, which was bypassed by
   overriding `command:` directly. Fixed with a dedicated `emptyDir` volume
   mounted at `/var/run/clamav`.

5. **minikube + docker driver image visibility.** Images built with a
   normal `docker build` on the host are invisible to minikube's internal
   Docker daemon. Fixed (for local/dev only) with
   `eval $(minikube docker-env)` before building, plus
   `imagePullPolicy: Never` on the watcher container.

6. **`inotify` does not work reliably over NFS.** Files written directly on
   the NFS server (or by another client) never triggered the watcher - no
   `Scanning:` log line ever appeared, despite `Watches established`
   printing at startup. This is a fundamental limitation: `inotify` is a
   local-filesystem kernel feature and does not propagate change
   notifications across NFS for writes made by other clients, regardless of
   NFS version. **Fixed by replacing the entire trigger mechanism** - the
   watcher now polls (`find` over `$SCAN_DIR` every `POLL_INTERVAL_SECONDS`)
   instead of using `inotifywait`, and considers a file "stable" (safe to
   scan) once its size is unchanged across two consecutive polls.

7. **Postgres `pg_hba.conf` allowed the wrong subnet.** `pg_hba.conf`
   permitted `192.168.49.0/24` (minikube's *node* network), but pods run on
   a separate *pod* network assigned by the CNI plugin (`10.244.0.0/16` in
   this Flannel setup, confirmed via `kubectl get pod -o wide`). Every
   insert from the watcher was silently rejected. Fixed by adding a
   `pg_hba.conf` entry for the actual pod CIDR. **General lesson:** node
   network, pod network, and service network are three different CIDR
   ranges in Kubernetes - always check the pod's actual IP rather than
   assuming it matches the node's subnet, for any externally-hosted service
   using IP-based access control.

8. **`clamdscan` CLI proved unreliable.** The `clamav-daemon` Debian package
   (providing the `clamdscan` client) had config-path resolution and
   client/daemon version-coupling issues in the slim watcher image. Fixed
   by dropping `clamav-daemon` entirely and writing a small Python script
   (`clamd_scan.py`) that speaks clamd's native `INSTREAM` protocol directly
   over a plain TCP socket - the same approach used internally by
   production clamd REST wrappers (e.g. `clamav-rest`). This removed an
   entire class of packaging/version problems and shrank the image's
   dependency footprint (just `python3`, no AV client tooling at all). TCP
   communication with `clamd` is not a security downgrade - the
   NetworkPolicy restricting which pods can reach port 3310 is the actual
   security boundary, unaffected by this change.


---

## 9. Known gaps before production

1. **Image distribution.** `imagePullPolicy: Never` + `minikube docker-env`
   only works for local single-node clusters. In production: push
   `av-watcher` to a real registry, reference the full
   `registry/repo:tag` path, set `imagePullPolicy: IfNotPresent` or
   `Always`, and pin to a specific tag/digest rather than `latest`.

2. **Secrets management.** `manifests/25-secret.yaml` as committed has
   plaintext placeholder credentials. Use `kubectl create secret generic`
   imperatively, or a proper secrets manager (Sealed Secrets, External
   Secrets Operator + Vault/AWS Secrets Manager/etc.) - never commit real
   values to this file.

3. **NFS server is a single VM, no redundancy.** Single point of failure
   for the entire pipeline. Use a properly available NFS service in
   production.

4. **PostgreSQL is unmanaged, unbacked-up.** Move to a managed service
   (RDS/Cloud SQL/etc.) or add a backup/replication strategy. Add
   connection pooling (PgBouncer) if scan volume grows, since the watcher
   opens a new `psql` connection per file.

5. **Single replica, `Recreate` strategy - cannot horizontally scale
   as-is.** Two replicas would both poll the same share and double-process
   every file. Scaling requires redesigning around a work queue (watcher
   publishes file paths to Redis/RabbitMQ/SQS, a separate scalable worker
   pool consumes from it) rather than every replica polling the filesystem
   directly.

6. **No recovery path for false positives.** Both flagged and errored files
   are deleted with no backup copy (see Problem 9 above). Consider a
   quarantine-move step (to a restricted, non-admin-visible share) instead
   of outright deletion if false-positive recovery matters for your use
   case - this is a tradeoff to make consciously.

7. **YARA ruleset is a placeholder.** Replace `starter.yar` with a real,
   maintained ruleset (YARA-Forge, Neo23x0/signature-base, or your own)
   before production. ConfigMaps cap out around 1MB - a serious ruleset may
   need a git-sync init container instead.

8. **NetworkPolicy egress for freshclam is `0.0.0.0/0` on 80/443.** Tighten
   to ClamAV's actual mirror CIDR ranges in production.

9. **Polling interval is a latency/load tradeoff.** Detection now has a
   delay of roughly `POLL_INTERVAL_SECONDS` x 2 (one cycle to notice the
   file, one more to confirm its size is stable) rather than being
   near-instant. Tune `POLL_INTERVAL_SECONDS` against NFS server load from
   constant `find` traversals.

10. **Resource sizing.** Current `clamd` limits (1Gi request / 2Gi limit)
    were sized for a quick POC. The signature DB grows over time - monitor
    actual usage and watch for OOMKills after DB updates.

11. **Observability.** Only `kubectl logs` and direct Postgres queries
    exist today. Before production: ship logs centrally, alert on
    `FLAGGED`/`ERROR` rows automatically, add a liveness/readiness probe on
    the `watcher` container itself (currently only `clamd` has one).
