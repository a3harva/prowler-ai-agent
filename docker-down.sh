#!/usr/bin/env bash
# Stops and completely removes the local dev stack's containers and networks.
# Pair with ./docker-up.sh for a clean restart after changing .env.local,
# docker-compose*.yml, Dockerfiles, or any dependency file (uv.lock /
# bun.lock) — those all require containers to be recreated, not just
# restarted.
#
# Postgres data lives in the ./postgres-data bind mount, NOT a named volume,
# so `docker compose down --volumes` does not touch it. Wiping the database
# now means deleting that directory, which this script does explicitly under
# --volumes rather than pretending compose will do it.
#
# Usage:
#   ./docker-down.sh             # remove containers + networks, keep postgres data
#   ./docker-down.sh --volumes   # also delete ./postgres-data (destroys the local DB)
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)

# ── Sibling containers Compose does not know about ───────────────────────────
# The worker launches Prowler (`prowler-scan-*`) and the recon cloud SDK
# (`cloud-cli-*`) through the Docker socket, not through Compose, so `down`
# leaves them running. That is worse than untidy: a surviving scanner keeps
# writing into ./reports with no worker left to import what it produces, and
# both hold VM memory indefinitely. The application reaps `cloud-cli-*` on
# worker startup, which only helps if a worker starts again.
#
# The host CLI and the worker talk to the same daemon — inside Colima's VM
# locally, the host's own daemon in production — so plain `docker` reaches
# them here with no DOCKER_HOST juggling.
reap_siblings() {
  local names
  names="$(docker ps -aq --filter "name=prowler-scan-" --filter "name=cloud-cli-" 2>/dev/null || true)"
  if [[ -n "$names" ]]; then
    echo "Removing sibling containers the worker launched outside Compose:"
    docker ps -a --filter "name=prowler-scan-" --filter "name=cloud-cli-" \
      --format '{{.Names}}  ({{.Status}})' 2>/dev/null | sed 's/^/  /' || true
    echo "  A scan interrupted this way stays 'running' in the database — re-submit it."
    docker rm -f $names >/dev/null 2>&1 || true
  fi
}

# ── Langfuse is in this project but not in these files ───────────────────────
# Compose derives the project from the directory, so the Langfuse services
# share it — but they are declared in docker-compose.langfuse.yml, which this
# script does not pass. To `--remove-orphans` they are therefore orphans, and
# it deletes them. Their named volumes are not in this file set either, so the
# traces survive and ./scripts/langfuse-up.sh brings it all back; still, a
# script that silently destroys six containers it never mentions is a script
# nobody can predict. Say so instead.
warn_about_langfuse() {
  local running
  running="$(docker ps -q --filter "name=${PWD##*/}-langfuse-" 2>/dev/null || true)"
  if [[ -n "$running" ]]; then
    echo "Langfuse is running. --remove-orphans will remove its containers too."
    echo "  Traces are kept — they live in named volumes this file set never touches,"
    echo "  and ./scripts/langfuse-up.sh restores everything."
    echo
  fi
}

if [[ "${1:-}" == "--volumes" ]]; then
  # This is the ONLY thing in the repo that destroys the local database.
  # `docker compose down --volumes` no longer can — the data is a bind mount,
  # not a named volume — so losing it has to be deliberate. Hence a safety
  # dump and a typed confirmation rather than a flag anyone can fat-finger.
  if [[ -d ./postgres-data/pgdata ]]; then
    if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx postgres; then
      echo "Taking a safety dump before wiping…"
      ./scripts/db-backup.sh pre-wipe || echo "  (dump failed — continuing, but nothing is recoverable)"
    else
      echo "postgres is not running, so no safety dump can be taken."
      echo "Start the stack and re-run if you want one."
    fi

    echo
    echo "About to DELETE ./postgres-data — every department, user, grant,"
    echo "organization and project in the local database goes with it."
    read -r -p "Type 'wipe' to confirm: " CONFIRM
    if [[ "$CONFIRM" != "wipe" ]]; then
      echo "Aborted — nothing was deleted, nothing was stopped."
      exit 1
    fi
  fi

  reap_siblings
  warn_about_langfuse
  "${COMPOSE[@]}" down --remove-orphans --volumes
  # Postgres runs as uid 999 inside the container, so the files it wrote are
  # not owned by the host user on Linux. Delete them from inside a throwaway
  # container to avoid needing sudo on the host.
  if [[ -d ./postgres-data ]]; then
    docker run --rm -v "$(pwd)/postgres-data:/data" alpine:3 sh -c 'rm -rf /data/..?* /data/.[!.]* /data/*' || true
    rmdir ./postgres-data 2>/dev/null || true
  fi
  echo "Database wiped. Restore the safety dump with ./scripts/db-restore.sh if that was a mistake."
else
  echo "Stopping and removing containers (postgres data preserved in ./postgres-data; pass --volumes to also wipe it)."
  reap_siblings
  warn_about_langfuse
  "${COMPOSE[@]}" down --remove-orphans
fi
