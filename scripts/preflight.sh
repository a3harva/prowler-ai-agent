#!/usr/bin/env bash
# Shared start-up checks for ./docker-up.sh and ./docker-watch.sh.
#
# Sourced, not executed — it defines functions and does nothing on its own.
# It exists because both entry scripts need the identical checks, and the
# Colima sizing block had already been copy-pasted into both: a fix applied to
# one and not the other is exactly the drift this consolidates away.

# ── Colima sizing ────────────────────────────────────────────────────────────
# Colima must run with 4 CPUs / 8 GiB or scans starve the control
# plane. Fix it here rather than failing partway through a scan.
preflight_colima() {
  command -v colima >/dev/null 2>&1 || return 0

  local status cpus memory_bytes
  status="$(colima list --json 2>/dev/null | jq -r 'select(.name=="default") | .status' || true)"
  cpus="$(colima list --json 2>/dev/null | jq -r 'select(.name=="default") | .cpus' || true)"
  memory_bytes="$(colima list --json 2>/dev/null | jq -r 'select(.name=="default") | .memory' || true)"

  if [[ "$status" == "Running" && ( "$cpus" != "4" || "$memory_bytes" != "8589934592" ) ]]; then
    echo "Colima is running with cpu=${cpus} memory_bytes=${memory_bytes}, not cpu=4 memory=8GiB — restarting it correctly."
    colima stop
    colima start --cpu 4 --memory 8
  elif [[ "$status" != "Running" ]]; then
    echo "Starting Colima with cpu=4 memory=8GiB."
    colima start --cpu 4 --memory 8
  fi
}

# ── .env.local must exist ────────────────────────────────────────────────────
# Without it Compose interpolates every variable to the empty string and the
# stack comes up half-configured: Postgres refuses its own healthcheck, and
# app/config.py fails startup on the first missing CONFIG_KEYS entry. Both are
# a long way from "you have no .env.local", which is the actual problem.
# scripts/langfuse-up.sh has always checked this; the app scripts did not.
preflight_env_file() {
  if [[ ! -f .env.local ]]; then
    echo "error: .env.local not found." >&2
    echo "       Copy .env.sample to .env.local and fill it in — Compose would" >&2
    echo "       otherwise start the stack with every variable empty." >&2
    exit 1
  fi
}

# ── HOST_REPORTS_PATH must name this checkout's ./reports ────────────────────
# The documented silent failure, and the reason it is worth a check rather than
# a comment: when this is stale the scan *succeeds*. Prowler writes a complete
# CSV, HTML, OCSF and all 21 compliance files into the old directory — which
# Docker creates on demand, since it is still under $HOME and therefore still
# mounted by Colima — and the worker then fails at import with
#
#   scan.csv not found at /reports/<id>/scan.csv — the scan container may not
#   have produced output
#
# which points at the scanner and is wrong. Nothing in the application can
# catch it: REPORTS_PATH is how the worker sees the directory, HOST_REPORTS_PATH
# is what the sibling container bind-mounts, and only the host knows they are
# meant to be the same place. docker-compose.local.yml mounts ./reports, so the
# correct value is always "$PWD/reports".
#
# Read with grep rather than sourced: .env.local holds secrets and this needs
# exactly one line of it.
preflight_reports_path() {
  local declared expected
  declared="$(sed -n 's/^HOST_REPORTS_PATH=//p' .env.local | tail -1 | tr -d '"'"'"'')"
  expected="$PWD/reports"

  if [[ -z "$declared" ]]; then
    echo "error: HOST_REPORTS_PATH is not set in .env.local." >&2
    echo "       Set it to: ${expected}" >&2
    exit 1
  fi

  if [[ "${declared%/}" != "${expected%/}" ]]; then
    echo "error: HOST_REPORTS_PATH does not name this checkout's reports directory." >&2
    echo "         .env.local says: ${declared}" >&2
    echo "         it must be:      ${expected}" >&2
    echo >&2
    echo "       This is the failure mode where the scan SUCCEEDS and the import" >&2
    echo "       fails with 'scan.csv not found' — the scanner writes everything" >&2
    echo "       into the stale directory. Fix the path before starting." >&2
    exit 1
  fi
}

# ── Schema must match the code ───────────────────────────────────────────────
# Nothing else runs migrations. Neither service has an entrypoint script: `api`
# goes straight to uvicorn and `worker` to run_worker, so restarting them after
# a `git pull` picks up new code against an old schema. That failure surfaces
# inside whichever task first touches the new column — a report that dies on a
# write reads as a report bug, not a missing migration.
#
# Ordering matters: postgres must be healthy first (--wait honours its
# healthcheck), and this runs in a throwaway container so it completes before
# api or worker ever start.
# Reads the caller's COMPOSE array as a global rather than taking it as an
# argument: `local -n` is bash 4.3+, and /usr/bin/env bash on macOS is 3.2.
preflight_migrate() {
  echo "Waiting for postgres, then applying migrations…"
  "${COMPOSE[@]}" up -d --wait postgres redis
  "${COMPOSE[@]}" build api
  "${COMPOSE[@]}" run --rm --no-deps api alembic upgrade head
}

# ── Everything, in the order it has to happen ────────────────────────────────
preflight_all() {
  preflight_env_file
  preflight_colima
  preflight_reports_path
  mkdir -p reports
  preflight_migrate
}
