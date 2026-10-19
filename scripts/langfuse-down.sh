#!/usr/bin/env bash
# Stops the Langfuse observability stack, leaving the application running.
#
# Usage:
#   ./scripts/langfuse-down.sh             # stop, keep the traces
#   ./scripts/langfuse-down.sh --volumes   # stop and delete every trace
#
# Unlike ./docker-down.sh --volumes, this one does not take a safety dump and
# does not make you type a word to confirm. That asymmetry is deliberate:
# traces are disposable telemetry, not customer data, and the application
# database is untouched by anything in this file. If you find yourself wanting
# a backup of these volumes, what you actually want is a longer retention
# setting inside Langfuse.
set -euo pipefail
cd "$(dirname "$0")/.."

# All three files, for the same reason langfuse-up.sh lists all three: invoking
# Compose with only the Langfuse file makes every application container look
# like an orphan.
COMPOSE=(docker compose
  -f docker-compose.yml
  -f docker-compose.local.yml
  -f docker-compose.langfuse.yml
  --env-file .env.local
  --profile langfuse)

SERVICES=(langfuse-web langfuse-worker clickhouse minio langfuse-postgres langfuse-redis)

if [[ "${1:-}" == "--volumes" ]]; then
  echo "Stopping Langfuse and deleting all trace data …"
  "${COMPOSE[@]}" rm -sf "${SERVICES[@]}"
  # Named, and named explicitly, so this can never reach the application's
  # volumes — `down --volumes` on a merged file set would.
  for vol in langfuse_postgres langfuse_clickhouse_data langfuse_clickhouse_logs langfuse_minio; do
    docker volume rm "$(basename "$PWD")_${vol}" >/dev/null 2>&1 \
      && echo "  removed ${vol}" \
      || echo "  ${vol} not present"
  done
  echo
  echo "Done. The application stack and its database are untouched."
  echo "The next ./scripts/langfuse-up.sh re-seeds the org, project and API keys"
  echo "from docker-compose.langfuse.yml, so nothing needs reconfiguring."
else
  echo "Stopping Langfuse, keeping traces …"
  "${COMPOSE[@]}" stop "${SERVICES[@]}"
  echo
  echo "Done. Reports generated while it is down are simply not traced — the"
  echo "client tolerates an unreachable collector and never fails a report."
fi
