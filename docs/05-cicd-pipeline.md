# 5. CI/CD Pipeline

File: `insurance_app/.github/workflows/build-and-push.yml`
Trigger: every push to `main`
Name: **Full DevSecOps Pipeline (CI/CD + Security)**

> The repo also contains `build-and-push.yml.save`, an earlier/broken
> iteration (it has YAML indentation errors and duplicate step blocks) —
> it is not used by GitHub Actions (only files literally named `*.yml`/`*.yaml`
> in `.github/workflows/` are picked up) and is kept here only as a
> before/after reference of how the pipeline evolved. Use `build-and-push.yml`.

## 5.1 Job graph

```
gitleaks ─┐
semgrep   ├──► build-images ──► trivy-image ──► push-images ──┬──► zap
trivy-fs ─┘                                                    └──► zap-backend
                                                                       │
                                                          send-security-report
                                                          (needs: all of the above,
                                                           runs even if some failed)
```

## 5.2 Job-by-job reference

### `gitleaks` — secret scanning
Runs `gitleaks/gitleaks-action@v2` in detect mode, JSON report
(`gitleaks.json`), `continue-on-error: true` (findings don't hard-fail the
pipeline — they flow into the central report instead). Uploaded as an
artifact.

### `semgrep` — SAST
Runs inside the official `semgrep/semgrep` container, `semgrep scan --config auto`,
JSON output (`semgrep.json`), `|| true` so it never fails the job on
findings.

### `trivy-fs` — filesystem/dependency scan
Installs Trivy via its official install script, scans the whole checked-out
repo (`trivy fs`), JSON output (`trivy-fs.json`), also non-blocking.

### `build-images` (needs: the three scans above)
Plain `docker build` of `./frontend` and `./backend` into local tags
(`frontend:test`, `backend:test`) — just to prove they build; not pushed
yet.

### `trivy-image` (needs: build-images)
Rebuilds both images (again, locally tagged) and runs
`trivy image --severity CRITICAL,HIGH --ignore-unfixed` against each,
JSON output for both (`trivy-frontend.json`, `trivy-backend.json`),
uploaded together as one `trivy-images` artifact.

### `push-images` (needs: trivy-image)
- Computes `IMAGE_BASE=ghcr.io/<owner>/<repo>` (lowercased — GHCR requires
  lowercase repo paths).
- Logs into GHCR using `github.actor` + the automatic `GITHUB_TOKEN`.
- Uses `docker/build-push-action@v6` to build **and** push both images,
  tagged both `:latest` and `:${{ github.sha }}`.

### `zap` (needs: push-images) — frontend DAST
- Pulls the freshly-pushed frontend image, runs it (`-p 8080:8080`).
- Waits (polling `curl`) for it to respond.
- Runs OWASP ZAP baseline scan (`ghcr.io/zaproxy/zaproxy:stable`,
  `zap-baseline.py`) against `http://localhost:8080`.
- Produces `zap.json` / `zap.md` / `zap.html`, uploaded as artifact `zap`.
- Always cleans up the container (`if: always()`).

### `zap-backend` (needs: push-images) — authenticated API DAST
This is the more involved job:
1. Creates a Docker network, starts a **throwaway MySQL** container on it
   seeded with a fresh `insurance` database.
2. Starts the backend image on that network with test env vars
   (`JWT_SECRET` from `secrets.ZAP_JWT`, `COOKIE_SECURE=false`, a
   throwaway `DATABASE_URL`).
3. Waits for the backend's `/api/car-models` endpoint to respond.
4. **Seeds a real admin user** directly into the throwaway MySQL database
   (hashing a password with `passlib[bcrypt]` inline in the workflow).
5. Logs in via `POST /api/login`, captures the `star_admin_session` cookie
   from `cookies.txt`.
6. Runs `zap-api-scan.py` against the backend's OpenAPI spec
   (`/openapi.json`), injecting the captured session cookie via ZAP's
   `replacer` config so the scan runs **authenticated** — this is what lets
   ZAP exercise endpoints that require login rather than only hitting
   public routes.
7. Cleans up the backend container, MySQL container, and network
   unconditionally.

### `send-security-report` (needs: all six jobs above, `if: always()`)
This is the fan-in step that makes the "central reporting" story work even
if earlier jobs failed or were skipped:
1. Downloads every artifact (`gitleaks`, `semgrep`, `trivy-fs`,
   `trivy-images`, `zap`, `zap-backend`) into `workspace-artifacts/`.
2. An inline Python script merges the two Trivy image reports into one
   `trivy-image.json`, and merges the frontend+backend ZAP `site` arrays
   into one `zap.json`.
3. Runs `insurance_app/scripts/build_security_report.py`, which reads all
   five normalized JSON files plus `COMMIT_SHA`/`BRANCH`/`RUN_ID` env vars
   and writes one `security-report.json` shaped like:
   ```json
   {
     "deployment": {"commit_sha": "...", "branch": "...", "github_run_id": "..."},
     "scans": [
       {"tool": "SEMGREP", "report": {...}},
       {"tool": "TRIVY_FS", "report": {...}},
       {"tool": "TRIVY_IMAGE", "report": {...}},
       {"tool": "GITLEAKS", "report": {"leaks": [...]}},
       {"tool": "ZAP", "report": {...}}
     ]
   }
   ```
4. POSTs that JSON to `$API_URL` (the `security-api` webhook, an ngrok URL
   in the current config) with header `X-API-KEY: ${{ secrets.API_KEY }}`.

## 5.3 Secrets and variables this workflow needs

Set these under **Settings → Secrets and variables → Actions** on your
GitHub repo:

| Name | Type | Purpose |
|---|---|---|
| `API_KEY` | Repository secret | Must match `security-api`'s `API_KEY` env var |
| `ZAP_JWT` | Repository secret | JWT signing secret for the throwaway backend used in the authenticated ZAP scan |

`GITHUB_TOKEN` is provided automatically by Actions; the workflow already
declares the `packages: write` permission it needs to push to GHCR.

Also update the hardcoded `env.API_URL` at the top of the workflow to point
at wherever you're running `security-api` (see
[06-security-reporting-api.md](06-security-reporting-api.md)).

## 5.4 Setting it up on your own fork

1. Fork/push the repo to your own GitHub account or org.
2. Add the `API_KEY` and `ZAP_JWT` repository secrets.
3. Update `env.API_URL` in the workflow to your `security-api` endpoint.
4. Confirm GHCR package visibility settings under your account/org (new
   packages default to private; make them public or configure the
   `ghcr-secret` pull secret in Kubernetes accordingly — see
   [08-kubernetes-deployment.md](08-kubernetes-deployment.md)).
5. Push to `main` and watch the **Actions** tab.

## 5.5 Why several scans use `|| true` / `continue-on-error: true`

Every scanner in this pipeline is intentionally **non-blocking** — a
finding does not stop the build. This is a deliberate design choice:
instead of failing loudly and leaving no record, every finding (however
severe) flows through to the central `security-api`/`security_findings`
table, where a human triages it in the Aegis dashboard. If you want a
hard gate instead (e.g. block merges on any CRITICAL), that's a policy
change to make deliberately per job — see
[12-troubleshooting-known-issues.md](12-troubleshooting-known-issues.md)
for the tradeoffs.
