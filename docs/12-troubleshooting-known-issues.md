# 12. Troubleshooting & Known Issues

## 12.1 CI/CD pipeline

| Symptom | Likely cause | Fix |
|---|---|---|
| `push-images` job fails to log into GHCR | Package visibility/permissions, or repo doesn't have `packages: write` | Confirm the workflow's top-level `permissions:` block includes `packages: write` (it does by default in `build-and-push.yml`); check org-level package creation policy if using an org account |
| `send-security-report` job's curl to `$API_URL` fails/times out | `security-api` isn't running, ngrok tunnel expired/changed URL, or `API_KEY` mismatch | Restart `security-api`, get a fresh ngrok URL, update `env.API_URL` in the workflow, verify the `API_KEY` repo secret matches the `security-api` `.env` |
| ngrok URL changes every restart | Free ngrok plan behavior | Use a paid ngrok static domain, or replace the tunnel entirely with a self-hosted GitHub Actions runner inside your network (no public exposure needed at all) |
| `zap-backend` job fails at "Wait for backend" | Throwaway MySQL didn't finish initializing before the backend tried to connect, or `DATABASE_URL` mismatch | Check the "Wait for MySQL" step logs; increase the retry loop if your runner is slow |
| Duplicate/garbled workflow steps if you look at `.github/workflows/build-and-push.yml.save` | That file is an earlier draft with real YAML syntax errors (missing `-` list markers under `zap:`) | Ignore it — GitHub Actions only executes `build-and-push.yml`; delete the `.save` file once you've confirmed you don't need it as a reference |

## 12.2 Kubernetes

| Symptom | Likely cause | Fix |
|---|---|---|
| Backend/frontend pods stuck `ImagePullBackOff` | `ghcr-secret` missing/wrong, or the image tag doesn't exist in your GHCR yet | `kubectl describe pod <name> -n devsecops` for the exact error; recreate `ghcr-secret` with a valid PAT (`read:packages` scope); confirm the tag was actually pushed by your own CI run, not the original author's SHA baked into the checked-in YAML |
| Backend pod `CrashLoopBackOff` | Can't reach MySQL, or `mysql-credentials` secret missing a key `DATABASE_URL` composition needs | `kubectl logs <backend-pod> -n devsecops`; verify `mysql-credentials` has `DB_USER`/`DB_PASSWORD`/`DB_NAME` |
| `scan-input`/`clean-output` PVCs stuck `Pending` | NFS server unreachable, or the PV's `nfs.server` IP wasn't updated from the placeholder | `kubectl describe pvc scan-input-nfs -n devsecops`; confirm NFS exports and firewall allow the cluster's node/pod CIDR |
| All MySQL data disappears after a pod restart | `emptyDir` volume by design in the current manifest (see [08-kubernetes-deployment.md](08-kubernetes-deployment.md) §8.7) | Switch to a `PersistentVolumeClaim` with real storage before relying on this for anything beyond a demo |
| Ingress returns 404/502 | `ingress-nginx` controller not installed, or ModSecurity annotations unsupported by your controller build | `kubectl get pods -n ingress-nginx`; confirm you're using the standard `ingress-nginx` controller image, not a different ingress implementation |

## 12.3 AV/YARA scanner

The in-repo `k8s/av/readme.md` §8 is a detailed, chronological "problems
faced" log from the original build — read it before debugging this
component, it covers (in order): wrong ClamAV image tag, ClamAV certs
hidden by a ConfigMap mount, `clamd`'s stdout log symlink loop, PID file
write permission, minikube image visibility, `inotify` not working over
NFS, `pg_hba.conf` subnet mismatch (pod network ≠ node network), and
`clamdscan` CLI reliability issues (replaced with a raw `INSTREAM` client).
Nearly every "why does this not work" question about this component is
already answered there.

Quick version of the most common ones:

| Symptom | Fix |
|---|---|
| Files never get scanned, no "Scanning:" log line | Confirm you're not relying on `inotify` — the design uses polling by necessity over NFS; check `watcher` container logs, not `clamd`'s |
| Watcher can't write to Postgres, no errors visible upstream | Check `pg_hba.conf` allows the **pod network CIDR** (not the node network) — `kubectl get pod <watcher-pod> -o wide -n av-scanning` to see the pod's actual IP/subnet |
| `clamd` fails to start, "Invalid certs directory" | A ConfigMap replaced the whole `/etc/clamav` directory; mount individual files via `subPath` instead (already done correctly in the checked-in `30-deployment.yaml` — only relevant if you're modifying it) |
| Locally built watcher image not found by minikube | Run `eval $(minikube docker-env)` before `docker build`, and use `imagePullPolicy: Never` for local-only testing |

## 12.4 Aegis dashboard

| Symptom | Likely cause | Fix |
|---|---|---|
| Deploy button fails with "No matching image line found" | `BACKEND_IMAGE_REPO`/`FRONTEND_IMAGE_REPO` constants in `app.py` don't match the actual `image:` line in your `deployment.yaml` files | Update the constants to your real GHCR namespace |
| Pods tab shows nothing / errors | `kubectl` not on `PATH` for the user running Streamlit, or no valid kubeconfig context | Run `kubectl get pods -n devsecops` manually as the same user/host first |
| AI fix suggestions never appear | `GROQ_API_KEY` unset | Expected — this feature is optional; set the key to enable it |
| Login always fails | No user created yet | Run `python3 create_admin.py` first |

## 12.5 Design tradeoffs worth knowing about (not bugs — deliberate choices)

- **Every CI security scan is non-blocking** (`|| true` / `continue-on-error`).
  Findings are recorded, not enforced. If you want hard gates (e.g. block
  merge on any CRITICAL Trivy finding), add that logic explicitly per job
  rather than assuming it already exists.
- **Two separate Postgres databases** (`security_reports` for CI findings,
  `av_scanner` for file-scan results) with **two separate login systems**
  reading from them (`security-api`'s API key vs. the dashboard's own
  `dashboard_users` table) — this is intentional separation of concerns,
  not duplication to clean up.
- **The Aegis dashboard edits real YAML files on disk and shells out to
  `kubectl apply`.** There's no dry-run, no diff preview, and no rollback
  button in the current code — treat the `k8s/` checkout on the dashboard's
  host as a real, git-tracked deployment source of truth so a bad apply is
  at least visible/revertible via `git diff` / `git checkout`.
- **AV scanner is single-replica by design**, not an oversight — see
  [09-av-yara-scanner.md](09-av-yara-scanner.md) §9.5 point 5 for why
  scaling it needs a redesign, not just a replica count bump.

## 12.6 If something isn't covered here

Check, in this order:
1. The specific component's document in this `docs/` folder.
2. `k8s/av/readme.md` (for anything AV/YARA-related — it's unusually
   detailed).
3. `insurance_app/README.md` (for basic app run instructions).
4. The actual source — every service in this project is small enough to
   read end-to-end in a few minutes (`security-api` is ~150 lines total
   across all files; `dashboard/app.py`, while long, is a single file with
   clearly named functions).
