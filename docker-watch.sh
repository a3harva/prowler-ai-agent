#!/usr/bin/env bash
# Day-to-day dev loop. Builds once, starts the stack, then stays in the
# foreground: api/worker/frontend rebuild automatically (and only) when
# their dependency files change (uv.lock, pyproject.toml, bun.lock,
# package.json, Dockerfile — see docker-compose.local.yml's `develop.watch`
# blocks). Everything else — plain source edits — already reaches the
# running containers live via the existing bind mounts + uvicorn --reload /
# Vite's watcher, so `watch` isn't duplicating that, only adding the one
# thing a bind mount can't do.
#
# Use this instead of repeatedly re-running ./docker-up.sh while iterating —
# that script force-rebuilds on every invocation, which is what piled up
# dozens of dangling images. Reach for ./docker-up.sh again only for a true
# cold start (first run, or after a change this script wouldn't catch, e.g.
# postgres-data structure or docker-compose.yml itself).
#
# Usage:
#   ./docker-watch.sh
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)

# The same preflight as docker-up.sh — .env.local, Colima sizing,
# HOST_REPORTS_PATH, ./reports and migrations. See scripts/preflight.sh.
# It lives there rather than being copy-pasted into both scripts, which is
# how the Colima block used to be: a fix applied to one and not the other.
. scripts/preflight.sh
preflight_all

"${COMPOSE[@]}" up --build --watch
