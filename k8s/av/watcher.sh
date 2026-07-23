#!/usr/bin/env bash
#
# watcher.sh
# Watches $SCAN_DIR on NFS for completed file writes, runs ClamAV (via clamdscan)
# and YARA against each new file, and records results in Postgres.
# On detection: LOG ONLY. File is left in place (no quarantine/delete).

set -uo pipefail

SCAN_DIR="${SCAN_DIR:-/scan-input}"
CLEAN_DIR="${CLEAN_DIR:-/clean-output}"
YARA_RULES="${YARA_RULES:-/rules/starter.yar}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-5}"
CLAMD_SOCKET_HOST="${CLAMD_SOCKET_HOST:-127.0.0.1}"
CLAMD_SOCKET_PORT="${CLAMD_SOCKET_PORT:-3310}"

PGHOST="${PGHOST:?PGHOST is required}"
PGPORT="${PGPORT:-5432}"
PGDATABASE="${PGDATABASE:?PGDATABASE is required}"
PGUSER="${PGUSER:?PGUSER is required}"
PGPASSWORD="${PGPASSWORD:?PGPASSWORD is required}"
export PGPASSWORD

NODE_NAME="${NODE_NAME:-unknown}"
POD_NAME="${POD_NAME:-unknown}"

log() {
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"
}

# Escape a value for safe inclusion in a single-quoted SQL literal
sql_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

write_result() {
    local file_path="$1" file_name="$2" file_size="$3" sha256="$4"
    local clamav_status="$5" clamav_sig="$6"
    local yara_status="$7" yara_matches_arr="$8"
    local overall="$9" raw_clam="${10}" raw_yara="${11}"

    psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1 -q <<SQL
INSERT INTO scan_results
    (file_path, file_name, file_size_bytes, sha256,
     clamav_status, clamav_signature,
     yara_status, yara_matches,
     overall_status, raw_clamav_output, raw_yara_output,
     host_node, pod_name)
VALUES
    ('$(sql_escape "$file_path")', '$(sql_escape "$file_name")', $file_size, '$(sql_escape "$sha256")',
     '$(sql_escape "$clamav_status")', $( [ -z "$clamav_sig" ] && echo NULL || echo "'$(sql_escape "$clamav_sig")'" ),
     '$(sql_escape "$yara_status")', $yara_matches_arr,
     '$(sql_escape "$overall")', '$(sql_escape "$raw_clam")', '$(sql_escape "$raw_yara")',
     '$(sql_escape "$NODE_NAME")', '$(sql_escape "$POD_NAME")');
SQL
    if [ $? -ne 0 ]; then
        log "ERROR: failed to write scan result for $file_path to Postgres"
    fi
}

scan_file() {
    local file_path="$1"

    # Guard: file may have been removed/moved again before we got to it
    if [ ! -f "$file_path" ]; then
        log "Skipping $file_path, no longer present"
        return
    fi

    local file_name file_size sha256
    file_name="$(basename "$file_path")"
    file_size="$(stat -c%s "$file_path" 2>/dev/null || echo 0)"
    sha256="$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')"

    log "Scanning: $file_path (size=$file_size sha256=$sha256)"

    # --- ClamAV (via clamd daemon, raw INSTREAM protocol - see clamd_scan.py) ---
    local clam_raw clam_status clam_sig clam_exit
    clam_raw="$(python3 /usr/local/bin/clamd_scan.py "$CLAMD_SOCKET_HOST" "$CLAMD_SOCKET_PORT" "$file_path" 2>&1)"
    clam_exit=$?
    if [ "$clam_exit" -eq 1 ]; then
        clam_status="INFECTED"
        clam_sig="$(echo "$clam_raw" | sed -E 's/^[^:]+: //')"
    elif [ "$clam_exit" -eq 0 ]; then
        clam_status="CLEAN"
        clam_sig=""
    else
        clam_status="ERROR"
        clam_sig=""
    fi

    # --- YARA ---
    #
    # IMPORTANT: stdout and stderr are captured SEPARATELY here.
    # yara writes actual rule matches to stdout, and compiler
    # warnings/errors (e.g. "rule X may slow down scanning") to stderr.
    # Previously these were merged with 2>&1, which meant a harmless
    # compile-time warning (present on every single invocation) made
    # $yara_raw non-empty every time, flagging every file regardless
    # of whether anything actually matched. -w also suppresses yara's
    # own warnings at the source as a second line of defense.
    local yara_stdout yara_stderr yara_status yara_matches_sql yara_stderr_file
    yara_stderr_file="$(mktemp)"
    yara_stdout="$(yara -w -r "$YARA_RULES" "$file_path" 2>"$yara_stderr_file")"
    yara_stderr="$(cat "$yara_stderr_file" 2>/dev/null)"
    rm -f "$yara_stderr_file"

    if [ -n "$yara_stderr" ]; then
        log "YARA warning/error for $file_path: $yara_stderr"
    fi

    if [ -n "$yara_stdout" ]; then
        yara_status="MATCH"
        # yara output: "<rule_name> <file_path>" per line -> build postgres TEXT[] literal
        local rules_csv
        rules_csv="$(echo "$yara_stdout" \
            | awk '{print $1}' \
            | sed "s/'/''/g" \
            | awk "{printf \"'%s',\", \$0}" \
            | sed 's/,$//')"
        yara_matches_sql="ARRAY[${rules_csv}]"
    else
        yara_status="CLEAN"
        yara_matches_sql="ARRAY[]::TEXT[]"
    fi
    # Keep the raw record limited to actual match output, not warning noise.
    local yara_raw="$yara_stdout"

    # --- Overall verdict ---
    local overall="CLEAN"
    if [ "$clam_status" = "INFECTED" ] || [ "$yara_status" = "MATCH" ]; then
        overall="FLAGGED"
    fi
    if [ "$clam_status" = "ERROR" ]; then
        overall="ERROR"
    fi

    if [ "$overall" = "FLAGGED" ]; then
        log "ALERT: $file_path flagged (clamav=$clam_status sig=${clam_sig:-none} yara=$yara_status) - DELETING from $SCAN_DIR"
        if rm -f "$file_path" 2>>/dev/stderr; then
            log "Deleted: $file_path"
        else
            log "ERROR: failed to delete flagged file $file_path - it remains in place, investigate permissions"
        fi
        # file_path is kept as-is (the original location) for the DB record,
        # even though the file no longer exists there - this preserves an
        # audit trail of where the infected file was found.
    elif [ "$overall" = "ERROR" ]; then
        log "ERROR scanning $file_path - leaving in place for re-check, not moving or deleting"
    else
        log "Result: $file_path -> CLEAN, moving to $CLEAN_DIR"
        mkdir -p "$(dirname "${CLEAN_DIR}/${file_name}")"
        if mv -n "$file_path" "${CLEAN_DIR}/${file_name}" 2>>/dev/stderr; then
            file_path="${CLEAN_DIR}/${file_name}"
        else
            log "ERROR: failed to move $file_path to $CLEAN_DIR (destination may already exist, or permissions issue)"
        fi
    fi

    write_result "$file_path" "$file_name" "$file_size" "$sha256" \
        "$clam_status" "$clam_sig" "$yara_status" "$yara_matches_sql" \
        "$overall" "$clam_raw" "$yara_raw"
}

log "Starting watcher on $SCAN_DIR -> clean files moved to $CLEAN_DIR (clamd=$CLAMD_SOCKET_HOST:$CLAMD_SOCKET_PORT, rules=$YARA_RULES)"

# Wait for clamd to be ready before entering the loop.
# zPING\0 is clamd's lightweight liveness command; expects "PONG" back.
clamd_ping() {
    python3 - "$CLAMD_SOCKET_HOST" "$CLAMD_SOCKET_PORT" <<'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(b"zPING\0")
        resp = s.recv(64)
        sys.exit(0 if b"PONG" in resp else 1)
except Exception:
    sys.exit(1)
PYEOF
}

until clamd_ping; do
    log "Waiting for clamd to become ready..."
    sleep 3
done
log "clamd is ready"

# NOTE: inotify is intentionally NOT used here. inotify is a local-filesystem
# kernel feature; it does not reliably propagate change notifications across
# NFS for writes made by other clients (e.g. an uploader writing directly to
# the NFS server, or a different pod/host writing to the same mount). Polling
# is the dependable approach for a shared NFS drop zone.
#
# Track already-processed files in-memory (associative array) so we don't
# rescan a file we've already handled. Combined with the move-to-clean-output
# step, this also naturally prevents reprocessing clean files (they're gone
# after the move); flagged/error files stay in place, so we track them here
# to avoid re-scanning every poll cycle.
declare -A seen_files
declare -A last_size

while true; do
    while IFS= read -r -d '' file_path; do
        # Skip files already fully processed (flagged/error files that
        # intentionally remain on disk)
        if [ -n "${seen_files[$file_path]+x}" ]; then
            continue
        fi

        current_size="$(stat -c%s "$file_path" 2>/dev/null || echo -1)"
        if [ "$current_size" = "-1" ]; then
            continue   # file vanished between find and stat
        fi

        prev_size="${last_size[$file_path]:--1}"
        if [ "$current_size" = "$prev_size" ]; then
            # Size unchanged since last poll -> treat as fully written, scan it
            scan_file "$file_path"
            seen_files["$file_path"]=1
            unset last_size["$file_path"]
        else
            # Still being written (or first time seen) -> wait one more cycle
            last_size["$file_path"]="$current_size"
        fi
    done < <(find "$SCAN_DIR" -type f -print0 2>/dev/null)

    sleep "$POLL_INTERVAL_SECONDS"
done
