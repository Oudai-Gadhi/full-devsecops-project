# 4. Local Development — Insurance App (Docker Compose)

This gets just the application (frontend + backend + MySQL) running on
your machine, with no Kubernetes, no security pipeline, no dashboard. Good
for day-to-day feature development.

## 4.1 Prerequisites

- Docker Engine + Docker Compose v2
- Linux, or WSL2/macOS with Docker Desktop (the repo's own instructions
  target Linux; commands below note the differences)

## 4.2 Steps

**1. Get the code**

```bash
git clone <your-fork-url> full-devsecops-project
cd full-devsecops-project/insurance_app
```

**2. Create the `.env` file**

`docker-compose.yml` reads these from `.env` in `insurance_app/` (this file
is git-ignored and must be created manually):

```bash
cat > .env << 'EOF'
MYSQL_ROOT_PASSWORD=change_me_root
MYSQL_DATABASE=insurance
MYSQL_USER=insurance_user
MYSQL_PASSWORD=change_me_app
DATABASE_URL=mysql+pymysql://insurance_user:change_me_app@db:3306/insurance
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-mailbox@gmail.com
SMTP_PASSWORD=your-gmail-app-password
EOF
```

> Note the backend's `DATABASE_URL` host is `db` — that's the Compose
> service name, not `localhost`, since containers talk to each other over
> the Compose network.
>
> SMTP is optional for local dev: if `SMTP_USER` is empty, the backend
> logs "Skipping email..." instead of failing (see `send_status_email` in
> `backend/main.py`).

**3. Fix uploads folder permissions**

The backend container runs as a non-root user (`uid 1001`); the mounted
uploads folder needs to be writable by it:

```bash
mkdir -p backend/uploads
chmod -R 777 backend/uploads
```

**4. Build and start everything**

```bash
docker compose up --build -d
```

(Older Compose installs may use the hyphenated `docker-compose up --build -d`
— both are referenced in the repo.)

**5. Verify**

```bash
docker compose ps
```

You should see three services: `db`, `backend`, `frontend`, all `Up`.

**6. Open the app**

| URL | What it is |
|---|---|
| http://localhost:5173 | Client accident-declaration form |
| http://localhost:5173/admin | Admin claims dashboard |
| http://localhost:8000/docs | FastAPI Swagger UI (all backend endpoints) |

## 4.3 Creating an admin user

The backend ships a helper script:

```bash
docker compose exec backend python hash_password.py
```

Use the resulting hash to insert a row into the `admin_users` table (via
`docker compose exec db mysql -u root -p`, or any MySQL client), or adapt
the script if it already writes the row for you — check
`backend/hash_password.py` in your checkout, since this is a one-off admin
bootstrap script, not an HTTP endpoint.

## 4.4 What each service actually does

| Service | Port | Detail |
|---|---|---|
| `db` | 3306 | MySQL 8.0, data persisted in the `mysql_data` named volume |
| `backend` | 8000 | FastAPI + Uvicorn; source is bind-mounted (`./backend:/app`) so code edits reload without rebuilding the image, similarly `./backend/uploads` is bind-mounted for persistence |
| `frontend` | 5173 | Built by a multi-stage Dockerfile (Vite build → nginx); source bind-mounted for local dev with `node_modules` kept in an anonymous volume so the container's own install isn't shadowed by your host's |

## 4.5 Stopping / resetting

```bash
docker compose down            # stop containers, keep volumes (DB data survives)
docker compose down -v         # stop and delete volumes (fresh DB next start)
```

## 4.6 Notable backend endpoints (see Swagger for full detail)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/car-models` | Reference data for the declaration form |
| `POST` | `/api/login` | Admin login, sets session cookie |
| `POST` | `/api/logout` | Clears session |
| `GET` | `/api/me` | Current admin identity |
| `POST` | `/api/claims` | Submit a new declaration (multipart, supports file attachments) |
| `GET` | `/api/claims` | List/filter claims (admin) |
| `GET` | `/api/attachments/{attachment_id}/file` | Download an attachment |

## 4.7 A note on the AV scanning path

In local Docker Compose, uploaded files just land in `backend/uploads` —
there is **no AV/YARA scanning** in this mode; that only happens when
`SCAN_INPUT_DIR`/`CLEAN_OUTPUT_DIR` point at the shared NFS volume used in
the Kubernetes deployment (see
[09-av-yara-scanner.md](09-av-yara-scanner.md)). Keep that in mind if
you're testing malicious-file handling — it needs the full K8s stack.
