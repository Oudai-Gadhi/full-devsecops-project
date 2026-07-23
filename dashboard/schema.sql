-- Run once against the av_scanner database:
--   psql -h $PGHOST -U $PGUSER -d $PGDATABASE -f schema.sql

-- Standalone login table for the Streamlit dashboard.
-- Not related to admin_users (that one belongs to the insurance backend).
CREATE TABLE IF NOT EXISTS dashboard_users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active     BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP
);

-- Additive audit columns for finding disposition (ignore / accept risk / postpone).
-- Existing rows are untouched; status keeps defaulting to 'OPEN' on insert
-- exactly as reports.py already does, so the ingestion pipeline needs no changes.
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS resolution_note TEXT;
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(64);
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;

-- Track whether/when a deployment was actually pushed via kubectl apply.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS deployed_at TIMESTAMP;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS deployed_by VARCHAR(64);
