-- Schema for AV/YARA scan results
CREATE TABLE IF NOT EXISTS scan_results (
    id              BIGSERIAL PRIMARY KEY,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_path       TEXT NOT NULL,
    file_name       TEXT NOT NULL,
    file_size_bytes BIGINT,
    sha256          TEXT,
    clamav_status   TEXT NOT NULL,        -- CLEAN | INFECTED | ERROR
    clamav_signature TEXT,                 -- e.g. Win.Trojan.Foo-1
    yara_status     TEXT NOT NULL,        -- CLEAN | MATCH | ERROR
    yara_matches    TEXT[],                -- list of matched rule names
    overall_status  TEXT NOT NULL,        -- CLEAN | FLAGGED | ERROR
    raw_clamav_output TEXT,
    raw_yara_output   TEXT,
    host_node       TEXT,
    pod_name        TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results (overall_status);
CREATE INDEX IF NOT EXISTS idx_scan_results_scanned_at ON scan_results (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256 ON scan_results (sha256);
