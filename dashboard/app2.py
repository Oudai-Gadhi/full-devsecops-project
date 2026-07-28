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

import pandas as pd
import plotly.graph_objects as go
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
BACKEND_IMAGE_REPO = "ghcr.io/oudai-gadhi/full-devsecops-project/backend"
FRONTEND_IMAGE_REPO = "ghcr.io/oudai-gadhi/full-devsecops-project/frontend"
BACKEND_DEPLOYMENT_YAML = "/home/oudai/full_proj/k8s/backend/deployment.yaml"
FRONTEND_DEPLOYMENT_YAML = "/home/oudai/full_proj/k8s/frontend/deployment.yaml"

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
dashboard. You are shown one finding at a time from Semgrep (SAST), Gitleaks (secrets), Trivy
(filesystem, container image, or IaC/config scanning), or OWASP ZAP (DAST). Every finding you
are shown already has a known fix available - never tell the user a finding is unfixed or that
no fix exists. If a Fixed version line is given, trust it literally.
 
Two services ship to production: a Python/FastAPI "backend" and an nginx "frontend" serving a
compiled static build. Both run as non-root with no shell exposed externally. The frontend is
built in a discarded multi-stage Docker stage (Node/npm) - only the compiled static output
actually ships. Use these facts only when they are actually relevant to the specific finding in
front of you - most findings won't need all of this context, and none of it should be treated as
a reason to wave away every finding you see.
 
TRIAGE RULES BY FINDING TYPE - reason about reachability and applicability, don't just default
everything to one verdict:
 
- Trivy IMAGE (package/CVE) findings: False Positive if the package only exists in the discarded
  frontend build stage (Node, npm, or a JS devDependency never present in the shipped image), OR
  if exploiting it strictly requires local shell or root access that neither container grants.
  Otherwise judge the CVE on its merits - a real RCE/deserialization/injection-class bug in a
  package the running process actually loads is True Positive.
 
- Trivy CONFIG findings (Dockerfile, Kubernetes manifests, other IaC): judge the misconfiguration
  itself against what the manifest/Dockerfile actually shows. These are True Positive by default -
  the non-root/no-shell reasoning above does NOT apply here, since a bad manifest setting (missing
  resource limits, an open ingress rule, a writable root filesystem, etc.) is a real gap regardless
  of which user the container runs as.
 
- Trivy filesystem findings not tied to a shipped container: treat like any other package finding -
  True Positive unless there's a specific, stated reason the code path is unreachable or unused.
 
- Semgrep, Gitleaks, and ZAP findings: default True Positive. These come from the app's own code,
  committed secrets, or the live running app - they are essentially never false positives given
  this stack's shape.
 
OUTPUT FORMAT - always exactly this shape, nothing else added:
Line 1: "Verdict: True Positive" or "Verdict: False Positive" followed by a dash and ONE concrete
  sentence grounded in the specific finding (never a generic "may not be exploitable" hedge).
Then: a numbered remediation list (max 4 steps), naming the exact file (requirements.txt,
  package.json, a Dockerfile, a specific K8s manifest field, or an application source file) to
  change. If the verdict is False Positive, replace the list with a single line telling the user
  to close it as a false positive and why - do not invent remediation steps for something not
  exploitable.
No other text: no restating the vulnerability description, no preamble, no closing remarks."""

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

st.set_page_config(page_title="Aegis — DevSecOps Control Center", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------
# Design tokens — light, enterprise SecOps theme (Slate / Indigo)
# --------------------------------------------------------------------------
BG = "#F4F6F9"
SIDEBAR_BG = "#FFFFFF"
SURFACE = "#FFFFFF"
SURFACE_ALT = "#F8FAFC"
BORDER = "rgba(15,23,42,0.09)"
BORDER_STRONG = "rgba(15,23,42,0.16)"
TEXT = "#0F172A"
TEXT_MUTED = "#475569"
TEXT_FAINT = "#64748B"
ACCENT = "#4338CA"
ACCENT_SOFT = "rgba(67,56,202,0.09)"
SUCCESS = "#059669"
SUCCESS_SOFT = "rgba(5,150,105,0.10)"
WARNING = "#D97706"
DANGER = "#DC2626"
CRITICAL = "#9F1239"
NEUTRAL = "#64748B"
CHART_GRID = "rgba(15,23,42,0.06)"

# Ordered, colorblind-considerate palette used across every chart so severity
# colors are always consistent between the KPI pills and the plotly figures.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

STATE_COLOR = {
    "CRITICAL": CRITICAL, "HIGH": DANGER, "MEDIUM": WARNING, "LOW": "#CA8A04", "INFO": NEUTRAL,
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
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .stApp {{ background: {BG}; color: {TEXT}; }}
        h1, h2, h3, h4 {{ font-family: 'Inter', sans-serif !important; color: {TEXT} !important; letter-spacing: -0.015em; font-weight: 700 !important; }}
        code, pre, .stCode {{ font-family: 'JetBrains Mono', monospace !important; }}
        p, span, div {{ letter-spacing: -0.002em; }}
        ::selection {{ background: {ACCENT_SOFT}; }}

        /* ---- layout ---- */
        .block-container {{ padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1440px; }}
        section[data-testid="stSidebar"] > div {{ padding-top: 1.2rem; }}
        section.main > div {{ background: {BG}; }}

        /* ---- header ---- */
        .eyebrow {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem; letter-spacing: 0.16em; text-transform: uppercase;
            color: {ACCENT}; margin-bottom: 3px; font-weight: 600;
        }}
        .aegis-title {{ font-size: 1.9rem; font-weight: 800; margin: 0; line-height: 1.15; color: {TEXT}; }}
        .aegis-subtitle {{ color: {TEXT_MUTED}; font-size: 0.88rem; margin-top: 2px; }}
        .aegis-logo-row {{ display:flex; align-items:center; gap:8px; }}
        .section-heading {{
            font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
            color: {TEXT_MUTED}; margin: 22px 0 10px 0; display:flex; align-items:center; gap:8px;
        }}
        .section-heading::after {{ content: ""; flex: 1; height: 1px; background: {BORDER}; }}

        /* ---- sidebar ---- */
        section[data-testid="stSidebar"] {{
            background: {SIDEBAR_BG} !important; border-right: 1px solid {BORDER};
            box-shadow: 2px 0 12px rgba(15,23,42,0.03);
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
            background: {SURFACE_ALT}; color: {TEXT} !important; border-color: {BORDER};
        }}
        section[data-testid="stSidebar"] .stButton > button[kind="primary"] {{
            background: {ACCENT_SOFT} !important; border: 1px solid rgba(67,56,202,0.30) !important;
            color: {ACCENT} !important; font-weight: 700;
        }}
        section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {{
            background: {ACCENT_SOFT} !important;
        }}
        section[data-testid="stSidebar"] .stButton > button [data-testid="stIconMaterial"] {{
            color: inherit !important; font-size: 1.05rem !important;
        }}
        section[data-testid="stSidebar"] hr {{ margin: 0.9rem 0; border-color: {BORDER} !important; }}
        .sidebar-user {{
            font-size: 0.72rem; color: {TEXT_FAINT}; font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase; letter-spacing: 0.08em;
        }}
        .sidebar-username {{ color: {TEXT}; font-weight: 700; font-size: 0.98rem; margin: 2px 0 10px 0; }}
        .sidebar-card {{
            background: {SURFACE_ALT}; border: 1px solid {BORDER}; border-radius: 10px;
            padding: 12px 14px; margin-bottom: 14px;
        }}

        /* ---- metrics / KPI cards ---- */
        div[data-testid="stMetric"] {{
            background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; padding: 14px 18px;
            box-shadow: 0 1px 2px rgba(15,23,42,0.04);
        }}
        div[data-testid="stMetricLabel"] {{
            font-family: 'JetBrains Mono', monospace; font-size: 0.66rem;
            letter-spacing: 0.07em; text-transform: uppercase; color: {TEXT_MUTED} !important;
        }}
        div[data-testid="stMetricValue"] {{ font-family: 'Inter', sans-serif; color: {TEXT} !important; font-weight: 800; }}
        div[data-testid="stMetricDelta"] svg {{ display: none; }}

        div[data-testid="stExpander"] {{ border: 1px solid {BORDER}; border-radius: 10px; background: {SURFACE}; }}
        div[data-testid="stExpander"] summary {{ font-weight: 600; color: {TEXT}; }}

        /* ---- buttons (main content) ---- */
        .stButton > button {{
            border-radius: 8px; border: 1px solid {BORDER}; background: {SURFACE};
            color: {TEXT}; font-weight: 600; transition: border-color 0.12s ease, background 0.12s ease;
        }}
        .stButton > button:hover {{ border-color: {ACCENT}; color: {ACCENT}; background: {ACCENT_SOFT}; }}
        .stButton > button[kind="primary"] {{ background: {ACCENT}; border-color: {ACCENT}; color: #fff; }}
        .stButton > button[kind="primary"]:hover {{ background: #3730A3; border-color: #3730A3; color: #fff; }}
        .stDownloadButton > button {{
            border-radius: 8px; border: 1px solid {BORDER}; background: {SURFACE}; color: {TEXT}; font-weight: 600;
        }}

        /* ---- chart / KPI panel cards ---- */
        .panel-card {{
            background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px;
            padding: 16px 18px 6px 18px; margin-bottom: 14px; height: 100%;
            box-shadow: 0 1px 2px rgba(15,23,42,0.04);
        }}
        .panel-title {{ font-weight: 700; font-size: 0.85rem; color: {TEXT}; margin-bottom: 2px; }}
        .panel-sub {{ font-size: 0.72rem; color: {TEXT_FAINT}; margin-bottom: 4px; }}

        /* ---- cards (rows: pods, findings, deployments, av) ---- */
        .spine-card {{
            background: {SURFACE}; border: 1px solid {BORDER};
            border-left: 3px solid var(--spine-color, {NEUTRAL});
            border-radius: 10px; padding: 13px 17px; margin-bottom: 9px;
            box-shadow: 0 1px 2px rgba(15,23,42,0.03);
            transition: border-color 0.12s ease, box-shadow 0.12s ease;
        }}
        .spine-card:hover {{ border-color: {BORDER_STRONG}; box-shadow: 0 2px 6px rgba(15,23,42,0.06); }}
        .spine-card .row {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px; }}
        .spine-title {{ font-weight: 600; font-size: 0.95rem; color: {TEXT}; }}
        .spine-sub {{ font-family: 'JetBrains Mono', monospace; color: {TEXT_MUTED}; font-size: 0.76rem; }}

        .pill {{
            display: inline-block; padding: 3px 10px; border-radius: 999px;
            font-size: 0.66rem; font-weight: 700; letter-spacing: 0.03em;
            font-family: 'JetBrains Mono', monospace;
        }}

        .pulse-dot {{
            display: inline-block; width: 7px; height: 7px; border-radius: 50%;
            background: {SUCCESS}; margin-right: 6px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 0 0 rgba(5, 150, 105, 0.45); }}
            70% {{ box-shadow: 0 0 0 8px rgba(5, 150, 105, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(5, 150, 105, 0); }}
        }}

        .sev-bar {{ display: flex; height: 7px; border-radius: 4px; overflow: hidden; background: {BORDER}; margin: 6px 0; }}
        .sev-bar-seg {{ height: 100%; }}
        .sev-legend {{ display: flex; gap: 11px; flex-wrap: wrap; font-size: 0.7rem; color: {TEXT_MUTED}; font-family: 'JetBrains Mono', monospace; }}
        .sev-legend .dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 4px; }}

        hr {{ border-color: {BORDER} !important; }}

        /* ---- dataframe / table polish ---- */
        div[data-testid="stDataFrame"] {{ border: 1px solid {BORDER}; border-radius: 10px; overflow: hidden; }}

        /* ---- tabs (st.tabs) ---- */
        button[data-baseweb="tab"] {{ font-weight: 600; color: {TEXT_MUTED}; }}
        button[data-baseweb="tab"][aria-selected="true"] {{ color: {ACCENT}; }}
        div[data-baseweb="tab-highlight"] {{ background-color: {ACCENT} !important; }}

        /* ---- inputs ---- */
        .stTextInput input, .stSelectbox div[data-baseweb="select"], .stDateInput input, .stMultiSelect div[data-baseweb="select"] {{
            border-radius: 8px !important;
        }}

        /* ---- responsive tweaks ---- */
        @media (max-width: 900px) {{
            .block-container {{ padding-left: 0.9rem; padding-right: 0.9rem; }}
            .aegis-title {{ font-size: 1.5rem; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# Chart theming — shared Plotly layout so every figure matches the dashboard
# --------------------------------------------------------------------------
CHART_FONT = dict(family="Inter, -apple-system, sans-serif", color=TEXT_MUTED, size=12)


def _themed_layout(fig, height=230, show_legend=False, margin=None):
    fig.update_layout(
        height=height,
        margin=margin or dict(l=8, r=8, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=CHART_FONT,
        showlegend=show_legend,
        legend=dict(orientation="h", yanchor="bottom", y=-0.28, font=dict(size=11), bgcolor="rgba(0,0,0,0)"),
        hoverlabel=dict(bgcolor=SURFACE, font_family="Inter", bordercolor=BORDER),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=BORDER, tickfont=dict(size=10.5))
    fig.update_yaxes(showgrid=True, gridcolor=CHART_GRID, zeroline=False, tickfont=dict(size=10.5))
    return fig


def donut_chart(counts, color_map, center_label="", center_sub=""):
    """counts: ordered dict/list of (label, value). Renders a donut with a center KPI."""
    labels = [l for l, v in counts if v > 0]
    values = [v for l, v in counts if v > 0]
    if not values:
        return None
    colors = [color_map.get(l, NEUTRAL) for l in labels]
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.68, marker=dict(colors=colors, line=dict(color=SURFACE, width=2)),
        sort=False, textinfo="none", hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    )])
    total = sum(values)
    fig.update_layout(
        annotations=[
            dict(text=f"<b>{total}</b>", x=0.5, y=0.58, font=dict(size=22, color=TEXT), showarrow=False),
            dict(text=center_sub or center_label, x=0.5, y=0.38, font=dict(size=10.5, color=TEXT_FAINT), showarrow=False),
        ],
    )
    return _themed_layout(fig, height=210, show_legend=True, margin=dict(l=8, r=8, t=8, b=28))


def bar_chart(x, y, colors=None, horizontal=False, height=230):
    if not x:
        return None
    if horizontal:
        fig = go.Figure(go.Bar(y=x, x=y, orientation="h", marker=dict(color=colors or ACCENT, line=dict(width=0)),
                                hovertemplate="%{y}: %{x}<extra></extra>"))
        fig.update_yaxes(autorange="reversed")
    else:
        fig = go.Figure(go.Bar(x=x, y=y, marker=dict(color=colors or ACCENT, line=dict(width=0)),
                                hovertemplate="%{x}: %{y}<extra></extra>"))
    return _themed_layout(fig, height=height)


def trend_chart(x, y, color=ACCENT, fill=True, height=230):
    if not x:
        return None
    fig = go.Figure(go.Scatter(
        x=x, y=y, mode="lines+markers", line=dict(color=color, width=2.5, shape="spline"),
        marker=dict(size=5, color=color), fill="tozeroy" if fill else None,
        fillcolor=f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.10)" if fill else None,
        hovertemplate="%{x}: %{y}<extra></extra>",
    ))
    return _themed_layout(fig, height=height)


def panel_open(title, sub=""):
    sub_html = f'<div class="panel-sub">{sub}</div>' if sub else ""
    st.markdown(f'<div class="panel-card"><div class="panel-title">{title}</div>{sub_html}', unsafe_allow_html=True)


def panel_close():
    st.markdown("</div>", unsafe_allow_html=True)


def section_heading(text):
    st.markdown(f'<div class="section-heading">{text}</div>', unsafe_allow_html=True)


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


def render_findings_overview(deployments, all_findings, open_findings):
    """Three chart panels giving triage teams an at-a-glance read before they
    scroll into individual deployments: severity mix, findings by tool, and
    the packages generating the most open findings."""
    col1, col2, col3 = st.columns(3)

    with col1:
        panel_open("Open findings by severity", f"{len(open_findings)} open across all deployments")
        sev_counts = {}
        for f in open_findings:
            sev = (f["severity"] or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ordered = [(s, sev_counts.get(s, 0)) for s in SEVERITY_ORDER]
        fig = donut_chart(ordered, STATE_COLOR, center_sub="open")
        if fig:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.caption("No open findings — clean slate.")
        panel_close()

    with col2:
        panel_open("Open findings by tool", "Semgrep · Gitleaks · Trivy · ZAP")
        tool_counts = {}
        for f in open_findings:
            tool_counts[f["tool"]] = tool_counts.get(f["tool"], 0) + 1
        tools_sorted = sorted(tool_counts.items(), key=lambda kv: kv[1], reverse=True)
        if tools_sorted:
            names = [t for t, _ in tools_sorted]
            fig = bar_chart(names, [c for _, c in tools_sorted], colors=ACCENT, height=210)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.caption("Nothing to chart yet.")
        panel_close()

    with col3:
        panel_open("Top affected packages", "Open findings, by package")
        pkg_counts = {}
        for f in open_findings:
            pkg = f.get("package_name")
            if pkg:
                pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
        pkgs_sorted = sorted(pkg_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]
        if pkgs_sorted:
            names = [p for p, _ in pkgs_sorted][::-1]
            counts = [c for _, c in pkgs_sorted][::-1]
            fig = bar_chart(names, counts, colors=CRITICAL, horizontal=True, height=210)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.caption("No package-level findings open.")
        panel_close()


@st.fragment
def security_findings_tab():
    deployments = get_dashboard_data()
    if not deployments:
        st.info("No deployments recorded yet.")
        return

    selected_id = st.session_state.get("selected_deployment_id")
    if selected_id is not None:
        dep = next((d for d in deployments if d["id"] == selected_id), None)
        if dep is None:
            st.session_state.selected_deployment_id = None
        else:
            deployment_detail_page(dep)
            return

    all_findings = [f for dep in deployments for f in dep["findings"]]
    open_findings = [f for f in all_findings if (f["status"] or "OPEN") == "OPEN"]

    section_heading("Overview")
    render_findings_overview(deployments, all_findings, open_findings)

    section_heading("Deployments &amp; findings")
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
        render_deployment_row(dep)


def render_deployment_row(dep):
    """Compact, clickable summary row for the deployments list. Clicking
    'Open deployment' navigates to deployment_detail_page(dep), which is
    where the per-deployment charts and the findings list itself live -
    this keeps the list itself cheap to render even with many deployments."""
    findings = dep["findings"]
    open_count = sum(1 for f in findings if (f["status"] or "OPEN") == "OPEN")
    total = len(findings)
    cleared_str = f"{total - open_count}/{total} cleared" if total else "no findings"
    dep_state = "DEPLOYED" if dep["status"] == "DEPLOYED" else ("OPEN" if open_count else "SUCCESS")

    sev_counts = {}
    for f in findings:
        if (f["status"] or "OPEN") == "OPEN":
            sev_counts[(f["severity"] or "INFO").upper()] = sev_counts.get((f["severity"] or "INFO").upper(), 0) + 1

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

    button_label = f"Open deployment ({total})" if total else "Open deployment"
    if action_cols[2].button(button_label, key=f"open_dep_{dep['id']}", icon=":material/bar_chart:", use_container_width=True):
        st.session_state.selected_deployment_id = dep["id"]
        st.rerun()

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)


def deployment_detail_page(dep):
    """Dedicated drill-down page for one deployment: header, KPI row, three
    charts scoped just to this deployment's findings, then the same bulk
    actions / filters / findings list the old inline expander used to show."""
    findings = dep["findings"]
    open_findings = [f for f in findings if (f["status"] or "OPEN") == "OPEN"]
    open_count = len(open_findings)
    total = len(findings)
    dep_state = "DEPLOYED" if dep["status"] == "DEPLOYED" else ("OPEN" if open_count else "SUCCESS")

    if st.button("← All deployments", key="back_to_deployments"):
        st.session_state.selected_deployment_id = None
        st.rerun()

    st.markdown(
        f"""
        <div class="row" style="margin-top:6px;">
            <div>
                <span class="aegis-title" style="font-size:1.4rem;">Deployment #{dep['id']}</span>
                &nbsp;&nbsp;{pill(dep_state.replace("_", " "), color_for(dep_state))}
            </div>
        </div>
        <div class="spine-sub" style="margin-top:4px;">
            {(dep['commit_sha'] or 'unknown')[:12]} · {dep['branch']} · run {dep['github_run_id']} · created {dep['created_at']}
        </div>
        """,
        unsafe_allow_html=True,
    )
    if dep["status"] == "DEPLOYED":
        st.markdown(
            f"{pill('DEPLOYED', ACCENT)} &nbsp;by {dep.get('deployed_by')} at {dep.get('deployed_at')}",
            unsafe_allow_html=True,
        )
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total findings", total)
    m2.metric("Open", open_count)
    m3.metric("Cleared", total - open_count)
    overdue = sum(
        1 for f in findings
        if f.get("due_date") and f["due_date"] < datetime.utcnow().date() and (f["status"] or "OPEN") in ("POSTPONED", "RISK_ACCEPTED")
    )
    m4.metric("Overdue", overdue, delta=None if overdue == 0 else "past fix-by date", delta_color="inverse")

    section_heading("Deployment breakdown")
    c1, c2, c3 = st.columns(3)

    with c1:
        panel_open("Open findings by severity")
        sev_counts = {}
        for f in open_findings:
            sev = (f["severity"] or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ordered = [(s, sev_counts.get(s, 0)) for s in SEVERITY_ORDER]
        fig = donut_chart(ordered, STATE_COLOR, center_sub="open")
        if fig:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key=f"dep_sev_{dep['id']}")
        else:
            st.caption("No open findings.")
        panel_close()

    with c2:
        panel_open("Findings by status")
        status_counts = {}
        for f in findings:
            s = (f["status"] or "OPEN").upper()
            status_counts[s] = status_counts.get(s, 0) + 1
        ordered = [(s, status_counts.get(s, 0)) for s in ["OPEN", "IGNORED", "POSTPONED", "RISK_ACCEPTED"]]
        fig = donut_chart(ordered, STATE_COLOR, center_sub="findings")
        if fig:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key=f"dep_status_{dep['id']}")
        else:
            st.caption("No findings.")
        panel_close()

    with c3:
        panel_open("Open findings by tool")
        tool_counts = {}
        for f in open_findings:
            tool_counts[f["tool"]] = tool_counts.get(f["tool"], 0) + 1
        tools_sorted = sorted(tool_counts.items(), key=lambda kv: kv[1], reverse=True)
        if tools_sorted:
            names = [t for t, _ in tools_sorted]
            fig = bar_chart(names, [c for _, c in tools_sorted], colors=ACCENT, height=210)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key=f"dep_tool_{dep['id']}")
        else:
            st.caption("Nothing to chart yet.")
        panel_close()

    section_heading("Actions")
    action_cols = st.columns([2, 2, 4])
    can_deploy = total > 0 and open_count == 0 and dep["status"] != "DEPLOYED"
    if dep["status"] == "DEPLOYED":
        action_cols[0].caption("Already deployed.")
    elif can_deploy:
        if action_cols[0].button(f"Deploy #{dep['id']}", key=f"deploy_detail_{dep['id']}", icon=":material/rocket_launch:", type="primary"):
            with st.spinner("Updating manifests and applying to cluster..."):
                ok, logs = deploy(dep["commit_sha"], dep["id"], st.session_state.username)
            st.toast("Deployed successfully" if ok else "Deploy failed", icon="🚀" if ok else "⚠️")
            st.code("\n".join(logs))
    else:
        action_cols[0].button(
            f"Deploy #{dep['id']}", key=f"deploy_detail_disabled_{dep['id']}", disabled=True,
            icon=":material/rocket_launch:", help="All findings must be Ignored or Postponed first.",
        )
    if findings:
        action_cols[1].download_button(
            "Export CSV", data=findings_to_csv(findings, dep["id"]),
            file_name=f"deployment_{dep['id']}_findings.csv", mime="text/csv",
            key=f"export_detail_{dep['id']}", icon=":material/download:",
        )

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

    section_heading("Findings")
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
def render_av_overview(rows):
    """Chart panels: clean vs flagged mix, and scan volume over time so a
    security lead can spot a spike (or a scanner that's gone quiet) fast."""
    clean = sum(1 for r in rows if r["overall_status"] == "CLEAN")
    flagged = len(rows) - clean

    col1, col2 = st.columns([1, 2])

    with col1:
        panel_open("Clean vs. flagged", f"{len(rows)} files scanned (most recent 500)")
        fig = donut_chart(
            [("CLEAN", clean), ("FLAGGED", flagged)],
            {"CLEAN": SUCCESS, "FLAGGED": DANGER},
            center_sub="scanned",
        )
        if fig:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        panel_close()

    with col2:
        panel_open("Scan volume over time", "Files scanned per day")
        dated = [r["scanned_at"].date() if hasattr(r["scanned_at"], "date") else r["scanned_at"] for r in rows if r.get("scanned_at")]
        if dated:
            df = pd.DataFrame({"day": dated})
            daily = df.groupby("day").size().reset_index(name="count").sort_values("day")
            fig = trend_chart(daily["day"].astype(str).tolist(), daily["count"].tolist(), color=ACCENT, height=210)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.caption("No timestamps to chart yet.")
        panel_close()


@st.fragment
def av_results_tab():
    rows = get_av_results()
    if not rows:
        st.info("No AV scan results yet.")
        return

    clean = sum(1 for r in rows if r["overall_status"] == "CLEAN")

    section_heading("Overview")
    render_av_overview(rows)

    section_heading("Scan results")
    m1, m2, m3 = st.columns(3)
    m1.metric("Scanned (recent)", len(rows))
    m2.metric("Clean", clean)
    m3.metric("Flagged", len(rows) - clean, delta=None if len(rows) - clean == 0 else "needs review", delta_color="inverse")
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
                if page["key"] != "findings":
                    st.session_state.selected_deployment_id = None
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

    if "selected_deployment_id" not in st.session_state:
        st.session_state.selected_deployment_id = None

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
        oc1.metric("Open findings", open_findings, delta=None if open_findings == 0 else f"{open_findings} unresolved", delta_color="inverse")
        oc2.metric("Awaiting deploy", pending_deploys)
        oc3.metric("Overdue", overdue_count, delta=None if overdue_count == 0 else "past fix-by date", delta_color="inverse")

    now_str = datetime.utcnow().strftime("%H:%M:%S UTC")
    st.markdown(
        f'<span class="pulse-dot"></span><span class="spine-sub">Live &middot; last sync {now_str} &middot; '
        f'data cached for {DASHBOARD_DATA_TTL}s (use \'Refresh all data\' in the sidebar for instant updates)</span>',
        unsafe_allow_html=True,
    )
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

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
