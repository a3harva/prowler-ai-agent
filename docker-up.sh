#!/usr/bin/env bash
# Rebuilds and starts the local dev stack, forcing a rebuild so any change to
# .env.local, docker-compose*.yml, Dockerfiles, uv.lock, or bun.lock is
# actually picked up rather than silently ignored by a stale image/container.
#
# Usage:
#   ./docker-up.sh          # rebuild + start, follow logs
#   ./docker-up.sh -d       # rebuild + start, detached
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)

# .env.local, Colima sizing, HOST_REPORTS_PATH, ./reports, and `alembic upgrade
# head` — see scripts/preflight.sh for why each one is worth the second it
# costs. Migrations run against a healthy postgres in a throwaway container,
# before api or worker start, so they can never come up against an old schema.
. scripts/preflight.sh
preflight_all

"${COMPOSE[@]}" up --build "$@"
