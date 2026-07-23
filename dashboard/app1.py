"""
AEGIS — DevSecOps Control Center

Pod health, deployment security triage, and AV results in one place.
Login persists across a browser refresh via a session token in the URL.

Run with:
    streamlit run app.py

DB connection uses standard PG* environment variables.
"""
import csv
import io
import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
import psycopg2.pool
import requests
import streamlit as st
from dotenv import load_dotenv
from passlib.context import CryptContext

# Load variables from a .env file sitting next to this script, so PGHOST/PGUSER/
# PGPASSWORD/PGDATABASE/PGPORT/GROQ_API_KEY etc. don't need exporting every session.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
BACKEND_IMAGE_REPO = "ghcr.io/oudai-gadhi/cloud-native-claims-platform/backend"
FRONTEND_IMAGE_REPO = "ghcr.io/oudai-gadhi/cloud-native-claims-platform/frontend"
BACKEND_DEPLOYMENT_YAML = "/home/oudai/k8s/backend/deployment.yaml"
FRONTEND_DEPLOYMENT_YAML = "/home/oudai/k8s/frontend/deployment.yaml"

NAMESPACES = ["devsecops", "av-scanning"]
# Risk Accepted removed as a selectable disposition - Ignored (with justification) and
# Postponed (with a fix-by date) cover the cases this dashboard needs.
DISPOSITION_OPTIONS = ["IGNORED", "POSTPONED"]
STATUS_FILTER_OPTIONS = ["OPEN", "IGNORED", "POSTPONED"]
SEVERITY_FILTER_OPTIONS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SESSION_LIFETIME_DAYS = 7

# cache lifetimes - tune here if things feel stale or slow
PODS_TTL = 6
KUBECTL_DETAIL_TTL = 6
DASHBOARD_DATA_TTL = 15
AV_RESULTS_TTL = 20
AI_FIX_TTL = 86400  # remediation advice for a given finding rarely changes

# --- Groq (AI fix suggestions) ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Fixed environment context so the model doesn't have to guess our stack.
# Kept deliberately narrow - the model was rambling about infra (NFS, namespaces)
# that's irrelevant to almost every finding, which is what caused hallucination.
INFRA_CONTEXT = """You are a security triage + remediation assistant embedded in a DevSecOps
dashboard. Every finding you are shown already has a fix available upstream (this dashboard
only sends you findings with a known fixed_version) - never tell the user a finding is
unfixed or that no upstream fix exists. If a Fixed version line is given, trust it literally.

STACK (ground every judgment in these actual facts, not generic assumptions):

Backend - single-stage image, python:3.11-slim base.
  - Build installs build-essential and libpq-dev via apt, then removes only the apt index
    (rm -rf /var/lib/apt/lists/*) - the packages themselves stay in the final image, they are
    not build-only.
  - App: FastAPI + SQLAlchemy + MySQL. Runs as non-root uid 1001. Listens on port 8000.
  - Dependency manifest: requirements.txt (Python packages installed via pip).

Frontend - multi-stage image.
  - Stage 1 (builder, discarded): node:20-alpine, npm ci, npm run build. Node, npm, and every
    JS devDependency/toolchain package live ONLY in this discarded build stage.
  - Stage 2 (shipped runtime): nginx:alpine serving the static build output plus a custom
    nginx.conf. Nothing from stage 1 is present except the compiled static files. Runs as
    non-root uid 1001. Listens on port 8080.
  - Dependency manifest: package.json / package-lock.json (JS packages, build-time only).

CI/CD: images built in CI, pushed to GHCR tagged with the git commit SHA. Shipping a new
image = bump the tag in the Kubernetes deployment.yaml and kubectl apply -f deployment.yaml.

Finding sources: Semgrep (SAST), Gitleaks (secrets), Trivy (filesystem scan AND container
image scan), OWASP ZAP (DAST against the running frontend).

OUTPUT FORMAT - always exactly this shape, nothing else added:
Line 1: "Verdict: True Positive" or "Verdict: False Positive" followed by a dash and ONE
  concrete sentence grounded in the stack facts above (never a generic "may not be
  exploitable" hedge).
Then: a numbered remediation list (max 4 steps). If the verdict is False Positive, replace
  the list with a single line telling the user to close it as a false positive / risk-accepted
  and why - do not invent remediation steps for something not exploitable.
No other text: no restating the vulnerability description, no preamble, no closing remarks.

VERDICT RULES - reason about reachability and applicability, not just severity:
- A Trivy IMAGE finding on a package from the frontend's build stage (node, npm, any JS
  devDependency, or a package only found in node:20-alpine) reported against the final
  frontend image: False Positive - that layer is discarded by the multi-stage build and is
  not present in what actually ships.
- A Trivy finding on build-essential, libpq-dev, or their transitive OS deps in the BACKEND
  image: these are genuinely present at runtime, so judge the actual CVE on its merits -
  usually True Positive if it is a memory-safety/RCE-class bug in a linked library, more
  arguable if it requires local shell access that the non-root, no-shell-exposed app doesn't
  grant.
- A vulnerability that requires root privileges, a setuid binary, or local interactive shell
  access to exploit is a False Positive here - both containers run as non-root uid 1001 with
  no shell exposed to the outside.
- A vulnerability in a package your code path never calls (e.g. a parser imported by a
  dependency the app never invokes) is a False Positive - name the unused code path if you
  can tell from the finding.
- Everything else (real RCE/deserialization/injection-class CVEs in packages actually loaded
  by the running FastAPI app or nginx process, and all Semgrep/Gitleaks/ZAP findings) defaults
  to True Positive.

REMEDIATION RULES (only apply when the verdict is True Positive):
- Only mention Kubernetes, kubectl, or redeploying if the fix genuinely requires shipping a
  new image (dependency/base-image bump) or the finding is literally about a Kubernetes or
  workflow YAML file. Semgrep, Gitleaks, and ZAP findings are almost always pure
  application/config fixes - name the exact file and change, no infra mentioned.
- Trivy IMAGE finding with a fixed_version: bump the exact package to that version in the
  correct manifest for this stack (requirements.txt for a Python package, package.json /
  package-lock.json for a JS package used in the frontend build stage, or the Dockerfile
  base-image tag / an explicit apt pin for an OS-level package) - then rebuild, push, update
  the tag in deployment.yaml, kubectl apply."""

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

st.set_page_config(page_title="Aegis — DevSecOps Control Center", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------
# Design tokens — dark, minimal, ngrok-inspired
# --------------------------------------------------------------------------
BG = "#0A0A0B"
SIDEBAR_BG = "#08080A"
SURFACE = "#131316"
SURFACE_ALT = "#0F0F12"
BORDER = "rgba(255,255,255,0.08)"
BORDER_STRONG = "rgba(255,255,255,0.16)"
TEXT = "#F5F5F7"
TEXT_MUTED = "#84848C"
TEXT_FAINT = "#57575F"
ACCENT = "#8B5CF6"
ACCENT_SOFT = "rgba(139,92,246,0.14)"
SUCCESS = "#34D399"
WARNING = "#F5A623"
DANGER = "#F2545B"
CRITICAL = "#D946EF"
NEUTRAL = "#5B5B66"

STATE_COLOR = {
    "CRITICAL": CRITICAL, "HIGH": DANGER, "MEDIUM": WARNING, "LOW": "#FACC15", "INFO": NEUTRAL,
    "OPEN": DANGER, "IGNORED": NEUTRAL, "RISK_ACCEPTED": SUCCESS, "POSTPONED": WARNING,
    "DEPLOYED": ACCENT, "SUCCESS": SUCCESS,
    "Running": SUCCESS, "Succeeded": SUCCESS,
    "Pending": WARNING, "ContainerCreating": WARNING,
    "Failed": DANGER, "CrashLoopBackOff": DANGER, "Error": DANGER,
    "CLEAN": SUCCESS, "INFECTED": DANGER,
}

PAGES = [
    {"key": "pods", "label": "Pods", "icon": ":material/dns:"},
    {"key": "findings", "label": "Security Findings", "icon": ":material/security:"},
    {"key": "av", "label": "AV Results", "icon": ":material/health_and_safety:"},
]


def color_for(state):
    return STATE_COLOR.get(state, NEUTRAL)


def inject_css():
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .stApp {{ background: {BG}; color: {TEXT}; }}
        h1, h2, h3, h4 {{ font-family: 'Inter', sans-serif !important; color: {TEXT} !important; letter-spacing: -0.015em; font-weight: 700 !important; }}
        code, pre, .stCode {{ font-family: 'JetBrains Mono', monospace !important; }}
        p, span, div {{ letter-spacing: -0.002em; }}

        /* ---- layout tightening for a faster, denser feel ---- */
        .block-container {{ padding-top: 1.6rem; padding-bottom: 2rem; max-width: 1400px; }}
        section[data-testid="stSidebar"] > div {{ padding-top: 1.2rem; }}

        /* ---- header ---- */
        .eyebrow {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem; letter-spacing: 0.16em; text-transform: uppercase;
            color: {ACCENT}; margin-bottom: 3px; font-weight: 500;
        }}
        .aegis-title {{ font-size: 1.9rem; font-weight: 700; margin: 0; line-height: 1.15; color: {TEXT}; }}
        .aegis-subtitle {{ color: {TEXT_MUTED}; font-size: 0.88rem; margin-top: 2px; }}
        .aegis-logo-row {{ display:flex; align-items:center; gap:8px; }}

        /* ---- sidebar ---- */
        section[data-testid="stSidebar"] {{
            background: {SIDEBAR_BG} !important; border-right: 1px solid {BORDER};
        }}
        section[data-testid="stSidebar"] .stButton > button {{
            width: 100%; justify-content: flex-start !important; text-align: left;
            background: transparent; border: 1px solid transparent; border-radius: 8px;
            color: {TEXT_MUTED} !important; font-weight: 500; font-size: 0.88rem;
            padding: 9px 12px; transition: background 0.12s ease, color 0.12s ease;
            box-shadow: none;
        }}
        section[data-testid="stSidebar"] .stButton > button p {{ color: inherit !important; text-align:left; }}
        section[data-testid="stSidebar"] .stButton > button:hover {{
            background: rgba(255,255,255,0.045); color: {TEXT} !important; border-color: {BORDER};
        }}
        section[data-testid="stSidebar"] .stButton > button[kind="primary"] {{
            background: {ACCENT_SOFT} !important; border: 1px solid rgba(139,92,246,0.35) !important;
            color: {TEXT} !important; font-weight: 600;
        }}
        section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {{
            background: {ACCENT_SOFT} !important;
        }}
        section[data-testid="stSidebar"] .stButton > button [data-testid="stIconMaterial"] {{
            color: inherit !important; font-size: 1.05rem !important;
        }}
        section[data-testid="stSidebar"] hr {{ margin: 0.9rem 0; border-color: {BORDER} !important; }}
        .sidebar-user {{
            font-size: 0.78rem; color: {TEXT_MUTED}; font-family: 'JetBrains Mono', monospace;
        }}
        .sidebar-username {{ color: {TEXT}; font-weight: 600; font-size: 0.98rem; margin: 2px 0 10px 0; }}

        /* ---- metrics ---- */
        div[data-testid="stMetric"] {{
            background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; padding: 14px 18px;
        }}
        div[data-testid="stMetricLabel"] {{
            font-family: 'JetBrains Mono', monospace; font-size: 0.68rem;
            letter-spacing: 0.07em; text-transform: uppercase; color: {TEXT_MUTED} !important;
        }}
        div[data-testid="stMetricValue"] {{ font-family: 'Inter', sans-serif; color: {TEXT} !important; font-weight: 700; }}

        div[data-testid="stExpander"] {{ border: 1px solid {BORDER}; border-radius: 10px; background: {SURFACE}; }}
        div[data-testid="stExpander"] summary {{ font-weight: 500; }}

        /* ---- buttons (main content) ---- */
        .stButton > button {{
            border-radius: 8px; border: 1px solid {BORDER}; background: {SURFACE_ALT};
            color: {TEXT}; font-weight: 500; transition: border-color 0.12s ease, background 0.12s ease;
        }}
        .stButton > button:hover {{ border-color: {ACCENT}; color: {TEXT}; background: {ACCENT_SOFT}; }}
        .stButton > button[kind="primary"] {{ background: {ACCENT}; border-color: {ACCENT}; color: #fff; }}
        .stDownloadButton > button {{
            border-radius: 8px; border: 1px solid {BORDER}; background: {SURFACE_ALT}; color: {TEXT};
        }}

        /* ---- cards ---- */
        .spine-card {{
            background: {SURFACE}; border: 1px solid {BORDER};
            border-left: 3px solid var(--spine-color, {NEUTRAL});
            border-radius: 10px; padding: 13px 17px; margin-bottom: 9px;
            transition: border-color 0.12s ease, transform 0.1s ease;
        }}
        .spine-card:hover {{ border-color: {BORDER_STRONG}; }}
        .spine-card .row {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px; }}
        .spine-title {{ font-weight: 600; font-size: 0.95rem; color: {TEXT}; }}
        .spine-sub {{ font-family: 'JetBrains Mono', monospace; color: {TEXT_MUTED}; font-size: 0.76rem; }}

        .pill {{
            display: inline-block; padding: 3px 10px; border-radius: 999px;
            font-size: 0.68rem; font-weight: 600; letter-spacing: 0.03em;
            font-family: 'JetBrains Mono', monospace;
        }}

        .pulse-dot {{
            display: inline-block; width: 7px; height: 7px; border-radius: 50%;
            background: {ACCENT}; margin-right: 6px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 0 0 rgba(139, 92, 246, 0.5); }}
            70% {{ box-shadow: 0 0 0 8px rgba(139, 92, 246, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(139, 92, 246, 0); }}
        }}

        .sev-bar {{ display: flex; height: 7px; border-radius: 4px; overflow: hidden; background: {BORDER}; margin: 6px 0; }}
        .sev-bar-seg {{ height: 100%; }}
        .sev-legend {{ display: flex; gap: 11px; flex-wrap: wrap; font-size: 0.7rem; color: {TEXT_MUTED}; font-family: 'JetBrains Mono', monospace; }}
        .sev-legend .dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 4px; }}

        hr {{ border-color: {BORDER} !important; }}

        /* ---- responsive tweaks ---- */
        @media (max-width: 900px) {{
            .block-container {{ padding-left: 0.9rem; padding-right: 0.9rem; }}
            .aegis-title {{ font-size: 1.5rem; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def pill(text, hex_color):
    return f'<span class="pill" style="background:{hex_color}22; color:{hex_color};">{text}</span>'


def spine_card_open(state):
    return f'<div class="spine-card" style="--spine-color:{color_for(state)};">'


def spine_card_close():
    return "</div>"


def severity_bar_html(counts):
    """counts: dict like {'CRITICAL': 2, 'HIGH': 5, ...}. Renders a proportional stacked bar + legend."""
    total = sum(counts.values())
    if total == 0:
        return ""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    segs = ""
    legend = ""
    for sev in order:
        c = counts.get(sev, 0)
        if c == 0:
            continue
        pct = (c / total) * 100
        color = color_for(sev)
        segs += f'<div class="sev-bar-seg" style="width:{pct}%; background:{color};"></div>'
        legend += f'<span><span class="dot" style="background:{color};"></span>{sev} {c}</span>'
    return f'<div class="sev-bar">{segs}</div><div class="sev-legend">{legend}</div>'


def due_date_badge(due_date, status):
    """Small pill showing how many days remain (or overdue) for a POSTPONED
    fix-by date or a RISK_ACCEPTED review-by date."""
    if not due_date:
        return ""
    today = datetime.utcnow().date()
    delta = (due_date - today).days
    if delta < 0:
        return pill(f"OVERDUE {abs(delta)}d", DANGER)
    if delta == 0:
        return pill("DUE TODAY", WARNING)
    if delta <= 3:
        return pill(f"{delta}d left", WARNING)
    return pill(f"{delta}d left", SUCCESS)


# --------------------------------------------------------------------------
# DB layer - pooled connections, cached reads
# --------------------------------------------------------------------------
@st.cache_resource
def get_pool():
    return psycopg2.pool.SimpleConnectionPool(1, 5)


def run_query(query, params=None, fetch=True):
    pool = get_pool()
    conn = pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params or ())
        rows = [dict(r) for r in cur.fetchall()] if fetch else None
        conn.commit()
        cur.close()
        return rows
    finally:
        pool.putconn(conn)


def ensure_session_table():
    run_query(
        """
        CREATE TABLE IF NOT EXISTS dashboard_sessions (
            token       VARCHAR(64) PRIMARY KEY,
            username    VARCHAR(64) NOT NULL,
            created_at  TIMESTAMP DEFAULT NOW(),
            expires_at  TIMESTAMP NOT NULL
        )
        """,
        fetch=False,
    )


@st.cache_data(ttl=DASHBOARD_DATA_TTL, show_spinner=False)
def get_dashboard_data():
    """One query for every deployment + its findings, instead of N+1 round trips."""
    rows = run_query(
        """
        SELECT d.id AS dep_id, d.github_run_id, d.commit_sha, d.branch,
               d.status AS dep_status, d.created_at AS dep_created_at,
               d.deployed_at, d.deployed_by,
               sf.id AS finding_id, sf.tool, sf.severity, sf.title, sf.description,
               sf.file_path, sf.line_number, sf.cve, sf.package_name, sf.installed_version,
               sf.fixed_version, sf.status AS finding_status, sf.resolved_by, sf.resolved_at,
               sf.resolution_note, sf.due_date
        FROM deployments d
        LEFT JOIN security_scans ss ON ss.deployment_id = d.id
        LEFT JOIN security_findings sf ON sf.scan_id = ss.id
        ORDER BY d.id DESC, sf.severity, sf.tool
        """
    )
    deployments = {}
    order = []
    for r in rows:
        did = r["dep_id"]
        if did not in deployments:
            deployments[did] = {
                "id": did, "github_run_id": r["github_run_id"], "commit_sha": r["commit_sha"],
                "branch": r["branch"], "status": r["dep_status"], "created_at": r["dep_created_at"],
                "deployed_at": r["deployed_at"], "deployed_by": r["deployed_by"], "findings": [],
            }
            order.append(did)
        if r["finding_id"] is not None:
            deployments[did]["findings"].append({
                "id": r["finding_id"], "tool": r["tool"], "severity": r["severity"],
                "title": r["title"], "description": r["description"], "file_path": r["file_path"],
                "line_number": r["line_number"], "cve": r["cve"], "package_name": r["package_name"],
                "installed_version": r["installed_version"], "fixed_version": r.get("fixed_version"),
                "status": r["finding_status"],
                "resolved_by": r["resolved_by"], "resolved_at": r["resolved_at"],
                "resolution_note": r["resolution_note"], "due_date": r.get("due_date"),
            })
    return [deployments[d] for d in order]


@st.cache_data(ttl=AV_RESULTS_TTL, show_spinner=False)
def get_av_results():
    return run_query("SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT 500")


def invalidate_dashboard_cache():
    get_dashboard_data.clear()


def invalidate_av_cache():
    get_av_results.clear()


def invalidate_pods_cache():
    get_pods.clear()
    kubectl_text_cached.clear()


# --------------------------------------------------------------------------
# Auth (persists across a browser refresh via ?token= in the URL)
# --------------------------------------------------------------------------
def check_login(username, password):
    rows = run_query(
        "SELECT * FROM dashboard_users WHERE username = %s AND is_active = TRUE", (username,)
    )
    if not rows or not pwd_context.verify(password, rows[0]["password_hash"]):
        return False
    run_query("UPDATE dashboard_users SET last_login_at = NOW() WHERE id = %s", (rows[0]["id"],), fetch=False)
    return True


def create_session(username):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_LIFETIME_DAYS)
    run_query(
        "INSERT INTO dashboard_sessions (token, username, expires_at) VALUES (%s, %s, %s)",
        (token, username, expires_at), fetch=False,
    )
    return token


def validate_session(token):
    rows = run_query(
        "SELECT username FROM dashboard_sessions WHERE token = %s AND expires_at > NOW()", (token,)
    )
    return rows[0]["username"] if rows else None


def destroy_session(token):
    run_query("DELETE FROM dashboard_sessions WHERE token = %s", (token,), fetch=False)


def restore_session_from_url():
    token = st.query_params.get("token")
    if not token:
        return False
    username = validate_session(token)
    if not username:
        return False
    st.session_state.logged_in = True
    st.session_state.username = username
    st.session_state.token = token
    return True


def login_screen():
    inject_css()
    st.markdown("<div style='height:14vh'></div>", unsafe_allow_html=True)
    _, mid, _ = st.columns([1, 1.1, 1])
    with mid:
        st.markdown(
            '<div class="aegis-logo-row"><span class="eyebrow">Security Operations</span></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="aegis-title">AEGIS</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="aegis-subtitle">Deployment security &amp; pod health control center</div><br>',
            unsafe_allow_html=True,
        )
        with st.container(border=True):
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Log in", use_container_width=True, type="primary", icon=":material/login:")
        if submitted:
            if check_login(username, password):
                token = create_session(username)
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.token = token
                st.query_params["token"] = token
                st.rerun()
            else:
                st.error("Invalid credentials.")


def logout():
    if "token" in st.session_state:
        destroy_session(st.session_state.token)
    st.session_state.logged_in = False
    st.query_params.clear()


# --------------------------------------------------------------------------
# Kubernetes helpers (cached - subprocess calls are the slow part)
# --------------------------------------------------------------------------
CLUSTER_UNREACHABLE = "CLUSTER_UNREACHABLE"


def _kubectl_json(args, timeout=4):
    try:
        result = subprocess.run(["kubectl"] + list(args) + ["-o", "json"], capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "connection refused" in stderr.lower() or "unable to connect" in stderr.lower():
                return None, CLUSTER_UNREACHABLE
            return None, stderr
        return json.loads(result.stdout), None
    except subprocess.TimeoutExpired:
        return None, CLUSTER_UNREACHABLE
    except Exception as e:
        return None, str(e)


def _kubectl_text(args, timeout=10):
    try:
        result = subprocess.run(["kubectl"] + list(args), capture_output=True, text=True, timeout=timeout)
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "(timed out reaching the cluster)"
    except Exception as e:
        return f"Error: {e}"


@st.cache_data(ttl=KUBECTL_DETAIL_TTL, show_spinner=False)
def kubectl_text_cached(args_tuple, timeout=10):
    return _kubectl_text(args_tuple, timeout=timeout)


@st.cache_data(ttl=PODS_TTL, show_spinner=False)
def get_pods(namespace):
    data, error = _kubectl_json(["get", "pods", "-n", namespace])
    if error:
        return None, error

    pods = []
    for item in data.get("items", []):
        name = item["metadata"]["name"]
        phase = item.get("status", {}).get("phase", "Unknown")
        statuses = item.get("status", {}).get("containerStatuses", [])
        ready = sum(1 for c in statuses if c.get("ready"))
        total = len(statuses)
        restarts = sum(c.get("restartCount", 0) for c in statuses)

        reason = phase
        for c in statuses:
            waiting = c.get("state", {}).get("waiting")
            if waiting:
                reason = waiting.get("reason", phase)

        pods.append({
            "name": name, "phase": phase, "reason": reason, "ready": f"{ready}/{total}",
            "restarts": restarts, "start_time": item.get("status", {}).get("startTime", "-"),
            "containers": [c["name"] for c in item.get("spec", {}).get("containers", [])],
        })
    return pods, None


def restart_pod(namespace, name):
    result = subprocess.run(["kubectl", "delete", "pod", name, "-n", namespace], capture_output=True, text=True, timeout=15)
    invalidate_pods_cache()
    return result.returncode == 0, (result.stdout + result.stderr).strip()


# --------------------------------------------------------------------------
# Pods tab
# --------------------------------------------------------------------------
def render_pod_card(namespace, p):
    st.markdown(
        f"""
        {spine_card_open(p['reason'])}
        <div class="row">
            <div>
                <span class="spine-title">{p['name']}</span>
                &nbsp;&nbsp;{pill(p['reason'], color_for(p['reason']))}
            </div>
            <div class="spine-sub">ready {p['ready']} · restarts {p['restarts']}</div>
        </div>
        <div class="spine-sub" style="margin-top:4px;">started {p['start_time']}</div>
        {spine_card_close()}
        """,
        unsafe_allow_html=True,
    )

    detail_key = f"detail_{namespace}_{p['name']}"
    show_detail = st.toggle("See more", key=detail_key)

    if show_detail:
        with st.expander("Details", expanded=True):
            dtab1, dtab2, dtab3 = st.tabs(["Describe", "Logs", "Actions"])
            with dtab1:
                describe_out = kubectl_text_cached(("describe", "pod", p["name"], "-n", namespace))
                st.code(describe_out or "(no output)", language="yaml")
            with dtab2:
                container = p["containers"][0] if p["containers"] else None
                if len(p["containers"]) > 1:
                    container = st.selectbox("Container", p["containers"], key=f"c_{namespace}_{p['name']}")
                log_args = ("logs", p["name"], "-n", namespace, "--tail=150") + (("-c", container) if container else ())
                logs_out = kubectl_text_cached(log_args)
                st.code(logs_out or "(no output)", language="bash")
            with dtab3:
                st.caption("Force-restart this pod (deletes it; the controller recreates it).")
                confirm = st.checkbox("I understand this will restart the pod", key=f"confirm_{namespace}_{p['name']}")
                if st.button("Restart pod", key=f"restart_{namespace}_{p['name']}", disabled=not confirm, icon=":material/restart_alt:"):
                    with st.spinner("Restarting..."):
                        ok, msg = restart_pod(namespace, p["name"])
                    st.toast(f"Pod {p['name']} restart requested" if ok else f"Restart failed: {msg}", icon="🔄" if ok else "⚠️")
                    st.rerun()


def render_pod_namespace(namespace):
    st.markdown(f"#### `{namespace}`")
    pods, error = get_pods(namespace)

    if error == CLUSTER_UNREACHABLE:
        st.markdown(
            f"""
            {spine_card_open("Failed")}
            <div class="row">
                <span class="spine-title">Cluster offline</span>
                {pill("NOT RUNNING", color_for("Failed"))}
            </div>
            <div class="spine-sub" style="margin-top:4px;">
                No response from the cluster — it's likely stopped (e.g. minikube not running).
            </div>
            {spine_card_close()}
            """,
            unsafe_allow_html=True,
        )
        return

    if error:
        st.error(f"Could not reach cluster for namespace `{namespace}`: {error}")
        return

    if not pods:
        st.info("No pods found in this namespace.")
        return

    running = sum(1 for p in pods if p["phase"] == "Running")
    m1, m2, m3 = st.columns(3)
    m1.metric("Total", len(pods))
    m2.metric("Running", running)
    m3.metric("Not healthy", len(pods) - running)
    st.markdown("<br>", unsafe_allow_html=True)

    for p in pods:
        render_pod_card(namespace, p)


@st.fragment
def pods_tab():
    top = st.columns([5, 1])
    top[0].markdown(
        '<span class="pulse-dot"></span><span class="spine-sub">live snapshot via kubectl (cached briefly for speed)</span>',
        unsafe_allow_html=True,
    )
    if top[1].button("Refresh", use_container_width=True, key="refresh_pods", icon=":material/refresh:"):
        invalidate_pods_cache()
        st.rerun()
    st.markdown("<br>", unsafe_allow_html=True)

    cols = st.columns(len(NAMESPACES))
    for col, ns in zip(cols, NAMESPACES):
        with col:
            render_pod_namespace(ns)


# --------------------------------------------------------------------------
# Deploy logic
# --------------------------------------------------------------------------
def update_image_tag(yaml_path, image_repo, new_tag):
    with open(yaml_path, "r") as f:
        content = f.read()
    pattern = re.compile(rf"(image:\s*{re.escape(image_repo)}:)[A-Za-z0-9]+")
    new_content, count = pattern.subn(rf"\g<1>{new_tag}", content)
    if count == 0:
        return False, f"No matching image line found for {image_repo} in {yaml_path}"
    with open(yaml_path, "w") as f:
        f.write(new_content)
    return True, f"Updated {yaml_path} -> {new_tag}"


def kubectl_apply(yaml_path):
    result = subprocess.run(["kubectl", "apply", "-f", yaml_path], capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr)


def deploy(commit_sha, deployment_id, username):
    logs = []
    ok_all = True
    for repo, yaml_path in [
        (BACKEND_IMAGE_REPO, BACKEND_DEPLOYMENT_YAML),
        (FRONTEND_IMAGE_REPO, FRONTEND_DEPLOYMENT_YAML),
    ]:
        ok, msg = update_image_tag(yaml_path, repo, commit_sha)
        logs.append(msg)
        if not ok:
            ok_all = False
            continue
        ok, output = kubectl_apply(yaml_path)
        logs.append(output.strip())
        if not ok:
            ok_all = False

    if ok_all:
        run_query(
            "UPDATE deployments SET status = 'DEPLOYED', deployed_at = NOW(), deployed_by = %s WHERE id = %s",
            (username, deployment_id), fetch=False,
        )
        invalidate_dashboard_cache()
    return ok_all, logs


# --------------------------------------------------------------------------
# Security Findings tab
# --------------------------------------------------------------------------
def resolve_finding(finding_id, disposition, note, username, due_date=None):
    run_query(
        """
        UPDATE security_findings
        SET status = %s, resolution_note = %s, resolved_by = %s, resolved_at = NOW(), due_date = %s
        WHERE id = %s
        """,
        (disposition, note, username, due_date, finding_id), fetch=False,
    )
    invalidate_dashboard_cache()


def reopen_finding(finding_id):
    run_query(
        """
        UPDATE security_findings
        SET status = 'OPEN', resolution_note = NULL, resolved_by = NULL, resolved_at = NULL, due_date = NULL
        WHERE id = %s
        """,
        (finding_id,), fetch=False,
    )
    invalidate_dashboard_cache()


def bulk_resolve_deployment(deployment_id, disposition, note, username, due_date=None):
    run_query(
        """
        UPDATE security_findings sf
        SET status = %s, resolution_note = %s, resolved_by = %s, resolved_at = NOW(), due_date = %s
        FROM security_scans ss
        WHERE sf.scan_id = ss.id
          AND ss.deployment_id = %s
          AND (sf.status = 'OPEN' OR sf.status IS NULL)
        """,
        (disposition, note, username, due_date, deployment_id), fetch=False,
    )
    invalidate_dashboard_cache()


FIXED_VERSION_PATTERNS = [
    re.compile(r"fixed in (?:version\s*)?v?([\w.\-]+)", re.IGNORECASE),
    re.compile(r"patched in (?:version\s*)?v?([\w.\-]+)", re.IGNORECASE),
    re.compile(r"resolved in (?:version\s*)?v?([\w.\-]+)", re.IGNORECASE),
    re.compile(r"upgrade to (?:version\s*)?v?([\w.\-]+)", re.IGNORECASE),
]


def extract_fixed_version_from_text(text):
    """Trivy's structured FixedVersion field is sometimes empty even when the
    description states one in plain English (e.g. "fixed in version 0.46.2").
    Catch that here instead of letting the model guess or wrongly claim 'no fix'."""
    if not text:
        return None
    for pattern in FIXED_VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).rstrip(".,;")
    return None


@st.cache_data(ttl=AI_FIX_TTL, show_spinner=False)
def get_ai_fix_steps(tool, severity, title, description, file_path, line_number,
                      cve, package_name, installed_version, fixed_version):
    if not GROQ_API_KEY:
        return "Set the GROQ_API_KEY environment variable to enable AI fix suggestions."

    # fixed_version now comes straight from the DB column (see get_dashboard_data) - this
    # dashboard only ever queues findings that have one. The text-regex fallback is just a
    # safety net for the rare row where the column is somehow still empty.
    effective_fixed_version = fixed_version or extract_fixed_version_from_text(description)

    details = [f"Tool: {tool}", f"Severity: {severity}", f"Title: {title}"]
    if description:
        details.append(f"Description: {description[:600]}")
    if file_path:
        details.append(f"File: {file_path}" + (f":{line_number}" if line_number else ""))
    if cve:
        details.append(f"CVE: {cve}")
    if package_name:
        details.append(f"Package: {package_name} (installed: {installed_version})")
    if effective_fixed_version:
        details.append(f"Fixed version: {effective_fixed_version}")
    elif package_name:
        details.append("Fixed version: not found in this row (unexpected - flag this to the dashboard owner rather than assuming no fix exists).")

    try:
        resp = requests.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": INFRA_CONTEXT},
                    {"role": "user", "content": "\n".join(details)},
                ],
                "temperature": 0.2,
                "max_tokens": 400,
            },
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Could not get AI suggestion: {e}"


def findings_to_csv(findings, dep_id=None):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["deployment_id", "tool", "severity", "title", "status", "cve", "package_name",
                      "installed_version", "file_path", "line_number", "resolved_by", "resolved_at",
                      "resolution_note", "due_date"])
    for f in findings:
        writer.writerow([
            dep_id, f["tool"], f["severity"], f["title"], f["status"], f.get("cve"), f.get("package_name"),
            f.get("installed_version"), f.get("file_path"), f.get("line_number"),
            f.get("resolved_by"), f.get("resolved_at"), f.get("resolution_note"), f.get("due_date"),
        ])
    return buf.getvalue()


def render_finding_row(f):
    sev = (f["severity"] or "INFO").upper()
    status = f["status"] or "OPEN"

    # Status (and severity, and due-date countdown) render here, outside the expander,
    # so they're visible at a glance without having to open every finding.
    # Built as one unbroken line (no leading whitespace/newlines) - indented multi-line
    # HTML can get parsed as a literal code block instead of rendered markup.
    due_html = ("&nbsp;" + due_date_badge(f.get("due_date"), status)) if f.get("due_date") else ""
    st.markdown(
        f'<div class="spine-card" style="--spine-color:{color_for(status)};">'
        f'<div class="row">'
        f'<span class="spine-title">[{f["tool"]}] {f["title"] or "(untitled)"}</span>'
        f'<div>{pill(sev, color_for(sev))}&nbsp;{pill(status.replace("_", " "), color_for(status))}{due_html}</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    with st.expander("Details"):
        if f.get("description"):
            st.markdown(f["description"], unsafe_allow_html=True)

        meta_cols = st.columns(4)
        if f.get("file_path"):
            meta_cols[0].caption(f"File: `{f['file_path']}`" + (f":{f['line_number']}" if f.get("line_number") else ""))
        if f.get("cve"):
            meta_cols[1].caption(f"CVE: `{f['cve']}`")
        if f.get("package_name"):
            meta_cols[2].caption(f"Package: `{f['package_name']}` ({f.get('installed_version')})")

        if status == "OPEN":
            fix_key = f"showfix_{f['id']}"
            if st.button("Suggest fix", key=f"fixbtn_{f['id']}", icon=":material/lightbulb:"):
                st.session_state[fix_key] = True
            if st.session_state.get(fix_key):
                with st.spinner("Asking AI for fix steps..."):
                    steps = get_ai_fix_steps(
                        f["tool"], sev, f["title"], f.get("description"),
                        f.get("file_path"), f.get("line_number"), f.get("cve"),
                        f.get("package_name"), f.get("installed_version"), f.get("fixed_version"),
                    )
                st.markdown(steps)

            disp_key = f"disp_{f['id']}"
            note_key = f"note_{f['id']}"
            due_key = f"due_{f['id']}"

            c1, c2 = st.columns([2, 3])
            disposition = c1.selectbox("Disposition", DISPOSITION_OPTIONS, key=disp_key)

            note_label = "Justification (required)" if disposition == "IGNORED" else "Note (optional)"
            note = c2.text_input(note_label, key=note_key)

            due_date = None
            if disposition == "POSTPONED":
                due_date = st.date_input(
                    "Fix by", key=due_key,
                    min_value=datetime.utcnow().date(),
                    value=datetime.utcnow().date() + timedelta(days=14),
                )

            error_msg = None
            if disposition == "IGNORED" and not note.strip():
                error_msg = "Ignoring a finding needs a justification — explain why it doesn't apply here."
            elif disposition == "POSTPONED" and not due_date:
                error_msg = "Pick a date to fix this by."

            if error_msg:
                st.caption(f":material/error: {error_msg}")

            if st.button("Apply", key=f"apply_{f['id']}", use_container_width=True, disabled=bool(error_msg)):
                resolve_finding(f["id"], disposition, note, st.session_state.username, due_date=due_date)
                st.toast("Disposition applied", icon="✅")
                st.rerun()
        else:
            st.caption(
                f"Resolved by **{f.get('resolved_by')}** on {f.get('resolved_at')}"
                + (f" — _{f['resolution_note']}_" if f.get("resolution_note") else "")
            )
            if f.get("due_date"):
                due_label = "Fix by" if status == "POSTPONED" else "Review by"
                st.markdown(
                    f'<span class="spine-sub">{due_label} {f["due_date"]}</span> &nbsp; {due_date_badge(f["due_date"], status)}',
                    unsafe_allow_html=True,
                )
            if st.button("Reopen", key=f"reopen_{f['id']}", icon=":material/undo:"):
                reopen_finding(f["id"])
                st.toast("Finding reopened", icon="↩️")
                st.rerun()


def finding_matches_filters(f, status_filter, severity_filter):
    if status_filter and (f["status"] or "OPEN") not in status_filter:
        return False
    if severity_filter and (f["severity"] or "INFO").upper() not in severity_filter:
        return False
    return True


def global_findings_search(deployments):
    with st.expander("Search across all findings", icon=":material/search:"):
        with st.form("global_search_form"):
            query = st.text_input("Search title / CVE / package")
            submitted = st.form_submit_button("Search")
        if submitted and query:
            q = query.lower()
            matches = []
            for dep in deployments:
                for f in dep["findings"]:
                    haystack = " ".join(str(x or "") for x in [f["title"], f.get("cve"), f.get("package_name")]).lower()
                    if q in haystack:
                        matches.append((dep["id"], f))
            st.caption(f"{len(matches)} match(es)")
            for dep_id, f in matches:
                sev = (f["severity"] or "INFO").upper()
                status = f["status"] or "OPEN"
                st.markdown(
                    f'Deployment #{dep_id} — {pill(sev, color_for(sev))} {pill(status, color_for(status))} '
                    f'[{f["tool"]}] {f["title"]}',
                    unsafe_allow_html=True,
                )


@st.fragment
def security_findings_tab():
    deployments = get_dashboard_data()
    if not deployments:
        st.info("No deployments recorded yet.")
        return

    all_findings = [f for dep in deployments for f in dep["findings"]]
    global_findings_search(deployments)

    if all_findings:
        st.download_button(
            "Export all findings (CSV)",
            data=findings_to_csv([{**f, "deployment_id": None} for f in all_findings]),
            file_name="all_security_findings.csv",
            mime="text/csv",
            icon=":material/download:",
        )
    st.markdown("<br>", unsafe_allow_html=True)

    for dep in deployments:
        render_deployment_card(dep)


def render_deployment_card(dep):
    """Renders one deployment as a compact row. Findings (and everything that
    creates per-finding widgets - selectboxes, text inputs, expanders) are only
    built when the card is expanded, via the `expanded` flag below. This is
    what makes the tab fast: with N deployments x M findings each, the old
    version instantiated every widget for every finding on every single
    rerun, whether you could see it or not. Now a collapsed card costs almost
    nothing.

    The status/severity filters below are scoped to this deployment only -
    each deployment card has its own filter state, keyed by dep['id']."""
    findings = dep["findings"]

    open_count = sum(1 for f in findings if (f["status"] or "OPEN") == "OPEN")
    total = len(findings)
    cleared_str = f"{total - open_count}/{total} cleared" if total else "no findings"
    dep_state = "DEPLOYED" if dep["status"] == "DEPLOYED" else ("OPEN" if open_count else "SUCCESS")

    sev_counts = {}
    for f in findings:
        if (f["status"] or "OPEN") == "OPEN":
            sev_counts[(f["severity"] or "INFO").upper()] = sev_counts.get((f["severity"] or "INFO").upper(), 0) + 1

    expand_key = f"expand_dep_{dep['id']}"
    expanded = st.session_state.get(expand_key, False)

    st.markdown(
        f"""
        {spine_card_open(dep_state)}

        <div class="row">
            <div>
                <span class="spine-title">Deployment #{dep['id']}</span>
                &nbsp;&nbsp;{pill(dep_state.replace("_", " "), color_for(dep_state))}
                <span class="spine-sub">&nbsp;&nbsp;{(dep['commit_sha'] or 'unknown')[:10]} · {dep['branch']}</span>
            </div>
            <div class="spine-sub">run {dep['github_run_id']} · {cleared_str}</div>
        </div>
        <div class="spine-sub" style="margin-top:4px;">{dep['created_at']}</div>
        {severity_bar_html(sev_counts)}
        {spine_card_close()}
        """,
        unsafe_allow_html=True,
    )

    action_cols = st.columns([2, 2, 2, 3])
    can_deploy = total > 0 and open_count == 0 and dep["status"] != "DEPLOYED"

    if dep["status"] == "DEPLOYED":
        action_cols[0].markdown(
            f"{pill('DEPLOYED', ACCENT)} &nbsp;by {dep.get('deployed_by')} at {dep.get('deployed_at')}",
            unsafe_allow_html=True,
        )
    elif can_deploy:
        if action_cols[0].button(f"Deploy #{dep['id']}", key=f"deploy_{dep['id']}", icon=":material/rocket_launch:", type="primary"):
            with st.spinner("Updating manifests and applying to cluster..."):
                ok, logs = deploy(dep["commit_sha"], dep["id"], st.session_state.username)
            st.toast("Deployed successfully" if ok else "Deploy failed", icon="🚀" if ok else "⚠️")
            st.code("\n".join(logs))
    else:
        action_cols[0].button(
            f"Deploy #{dep['id']}", key=f"deploy_disabled_{dep['id']}", disabled=True,
            icon=":material/rocket_launch:",
            help="All findings must be Ignored or Postponed first.",
        )

    if findings:
        action_cols[1].download_button(
            "Export CSV", data=findings_to_csv(findings, dep["id"]),
            file_name=f"deployment_{dep['id']}_findings.csv", mime="text/csv",
            key=f"export_{dep['id']}", icon=":material/download:",
        )

    if total:
        toggle_label = "Hide findings" if expanded else f"View findings ({total})"
        toggle_icon = ":material/expand_less:" if expanded else ":material/expand_more:"
        if action_cols[2].button(toggle_label, key=f"toggle_{expand_key}", icon=toggle_icon):
            st.session_state[expand_key] = not expanded
            st.rerun()
    else:
        action_cols[2].caption("No findings for this deployment.")

    if not (total and expanded):
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        return

    st.markdown("<div style='height:2px'></div>", unsafe_allow_html=True)

    if open_count > 1:
        with st.expander(f"Bulk-apply to all {open_count} open findings", icon=":material/checklist:"):
            bulk_disp_key = f"bulk_disp_{dep['id']}"
            bc1, bc2 = st.columns([2, 3])
            bulk_disp = bc1.selectbox("Disposition", DISPOSITION_OPTIONS, key=bulk_disp_key)

            bulk_note_label = "Justification (required)" if bulk_disp == "IGNORED" else "Note (optional)"
            bulk_note = bc2.text_input(bulk_note_label, key=f"bulk_note_{dep['id']}")

            bulk_due = None
            if bulk_disp == "POSTPONED":
                bulk_due = st.date_input(
                    "Fix by", key=f"bulk_due_{dep['id']}",
                    min_value=datetime.utcnow().date(),
                    value=datetime.utcnow().date() + timedelta(days=14),
                )

            bulk_error = None
            if bulk_disp == "IGNORED" and not bulk_note.strip():
                bulk_error = "Ignoring findings needs a justification."
            elif bulk_disp == "POSTPONED" and not bulk_due:
                bulk_error = "Pick a date to fix these by."

            if bulk_error:
                st.caption(f":material/error: {bulk_error}")

            if st.button("Apply to all", key=f"bulk_apply_{dep['id']}", use_container_width=True, disabled=bool(bulk_error)):
                bulk_resolve_deployment(dep["id"], bulk_disp, bulk_note, st.session_state.username, due_date=bulk_due)
                st.toast(f"Applied {bulk_disp} to {open_count} findings", icon="✅")
                st.rerun()

    c1, c2 = st.columns(2)
    status_filter = c1.multiselect(
        "Status", STATUS_FILTER_OPTIONS, key=f"status_filter_{dep['id']}",
        placeholder="All statuses",
    )
    severity_filter = c2.multiselect(
        "Severity", SEVERITY_FILTER_OPTIONS, key=f"severity_filter_{dep['id']}",
        placeholder="All severities",
    )

    visible_findings = [
        f for f in findings if finding_matches_filters(f, status_filter, severity_filter)
    ]
    if (status_filter or severity_filter) and not visible_findings:
        st.caption("No findings in this deployment match the current filter.")
    for f in visible_findings:
        render_finding_row(f)
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)


# --------------------------------------------------------------------------
# AV Results tab
# --------------------------------------------------------------------------
@st.fragment
def av_results_tab():
    rows = get_av_results()
    if not rows:
        st.info("No AV scan results yet.")
        return

    clean = sum(1 for r in rows if r["overall_status"] == "CLEAN")
    m1, m2, m3 = st.columns(3)
    m1.metric("Scanned (recent)", len(rows))
    m2.metric("Clean", clean)
    m3.metric("Flagged", len(rows) - clean)
    st.markdown("<br>", unsafe_allow_html=True)

    with st.form("av_filter_form"):
        col1, col2 = st.columns(2)
        status_filter = col1.multiselect(
            "Filter by overall status",
            options=sorted({r["overall_status"] for r in rows if r["overall_status"]}),
        )
        search = col2.text_input("Search filename")
        st.form_submit_button("Apply filters", icon=":material/filter_alt:")

    filtered = rows
    if status_filter:
        filtered = [r for r in filtered if r["overall_status"] in status_filter]
    if search:
        filtered = [r for r in filtered if search.lower() in (r["file_name"] or "").lower()]

    st.caption(f"{len(filtered)} of {len(rows)} results")

    page_key = "av_page_size"
    if page_key not in st.session_state:
        st.session_state[page_key] = 25

    visible = filtered[: st.session_state[page_key]]

    for r in visible:
        state = r["overall_status"] or "UNKNOWN"
        st.markdown(
            f"""
            {spine_card_open(state)}
            <div class="row">
                <span class="spine-title">{r['file_name']}</span>
                {pill(state, color_for(state))}
            </div>
            <div class="spine-sub" style="margin-top:4px;">{r['scanned_at']}</div>
            {spine_card_close()}
            """,
            unsafe_allow_html=True,
        )
        with st.expander("Details"):
            c1, c2 = st.columns(2)
            c1.write(f"**Path:** `{r['file_path']}`")
            c1.write(f"**Size:** {r['file_size_bytes']} bytes")
            c1.write(f"**SHA256:** `{r['sha256']}`")
            c1.write(f"**Host node:** {r['host_node']} · **Pod:** {r['pod_name']}")
            c2.write(f"**ClamAV:** {r['clamav_status']} {r.get('clamav_signature') or ''}")
            c2.write(f"**YARA:** {r['yara_status']} · matches: {r['yara_matches']}")
            if r.get("raw_clamav_output"):
                st.caption("ClamAV output")
                st.code(r["raw_clamav_output"])
            if r.get("raw_yara_output"):
                st.caption("YARA output")
                st.code(r["raw_yara_output"])

    if len(filtered) > len(visible):
        if st.button(f"Load more ({len(filtered) - len(visible)} remaining)", icon=":material/expand_more:"):
            st.session_state[page_key] += 25
            st.rerun()


# --------------------------------------------------------------------------
# Sidebar navigation
# --------------------------------------------------------------------------
def render_sidebar(open_findings):
    if "active_page" not in st.session_state:
        st.session_state.active_page = "pods"

    with st.sidebar:
        st.markdown(
            '<div class="aegis-logo-row"><span class="eyebrow">Security Operations</span></div>'
            '<div class="aegis-title" style="font-size:1.4rem;">AEGIS</div>',
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

        badges = {"findings": open_findings}
        for page in PAGES:
            is_active = st.session_state.active_page == page["key"]
            label = page["label"]
            if badges.get(page["key"]):
                label = f"{label}  ({badges[page['key']]})"
            if st.button(
                label, key=f"nav_{page['key']}", icon=page["icon"],
                use_container_width=True, type="primary" if is_active else "secondary",
            ):
                st.session_state.active_page = page["key"]
                st.rerun()

        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div class="sidebar-user">Signed in</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="sidebar-username">{st.session_state.username}</div>', unsafe_allow_html=True)

        auto_refresh = st.checkbox("Auto-refresh every 10s")
        if st.button("Refresh all data", use_container_width=True, icon=":material/refresh:"):
            invalidate_dashboard_cache()
            invalidate_av_cache()
            invalidate_pods_cache()
            st.rerun()
        if st.button("Log out", use_container_width=True, icon=":material/logout:"):
            logout()
            st.rerun()

    return st.session_state.active_page, auto_refresh


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        ensure_session_table()
        restore_session_from_url()

    if not st.session_state.logged_in:
        login_screen()
        return

    inject_css()

    # Cheap, cached call - needed for the header metric and the sidebar badge.
    # Deliberately NOT calling get_pods()/get_av_results() here: those stay
    # scoped to their own page so switching tabs doesn't pay for work you
    # can't see (this is what made the old tabbed layout feel slow).
    deployments = get_dashboard_data()
    open_findings = sum(1 for dep in deployments for f in dep["findings"] if (f["status"] or "OPEN") == "OPEN")
    pending_deploys = sum(1 for dep in deployments if dep["status"] != "DEPLOYED")
    today = datetime.utcnow().date()
    overdue_count = sum(
        1 for dep in deployments for f in dep["findings"]
        if f.get("due_date") and f["due_date"] < today and (f["status"] or "OPEN") in ("POSTPONED", "RISK_ACCEPTED")
    )

    active_page, auto_refresh = render_sidebar(open_findings)

    if auto_refresh:
        st.markdown('<meta http-equiv="refresh" content="10">', unsafe_allow_html=True)

    header_col1, header_col2 = st.columns([3, 2])
    with header_col1:
        page_meta = next(p for p in PAGES if p["key"] == active_page)
        st.markdown('<div class="eyebrow">Security Operations</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="aegis-title">{page_meta["label"]}</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="aegis-subtitle">Deployment security &amp; pod health control center</div>',
            unsafe_allow_html=True,
        )
    with header_col2:
        oc1, oc2, oc3 = st.columns(3)
        oc1.metric("Open findings", open_findings)
        oc2.metric("Awaiting deploy", pending_deploys)
        oc3.metric("Overdue", overdue_count)

    st.caption(f"Data cached for speed — refreshed within the last {DASHBOARD_DATA_TTL}s (use 'Refresh all data' in the sidebar for instant updates).")
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # Only the active page's function runs - this is the main perf fix vs. the
    # old st.tabs layout, which executed every tab's body (including kubectl
    # subprocess calls) on every single rerun regardless of which was visible.
    if active_page == "pods":
        pods_tab()
    elif active_page == "findings":
        security_findings_tab()
    elif active_page == "av":
        av_results_tab()


if __name__ == "__main__":
    main()
