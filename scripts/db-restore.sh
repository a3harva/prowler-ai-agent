#!/usr/bin/env bash
# Restores a dump produced by ./scripts/db-backup.sh.
#
# This REPLACES the current contents of the database. It takes a safety dump
# of the existing data first, so a restore onto the wrong database is itself
# recoverable.
#
# Usage:
#   ./scripts/db-restore.sh backups/prowler-20260817-034500.dump
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)

DUMP="${1:-}"
if [[ -z "$DUMP" ]]; then
  echo "Usage: ./scripts/db-restore.sh <dump-file>" >&2
  echo "Available:" >&2
  ls -1t backups/*.dump 2>/dev/null | head -10 >&2 || echo "  (none in ./backups)" >&2
  exit 1
fi
if [[ ! -f "$DUMP" ]]; then
  echo "No such dump: $DUMP" >&2
  exit 1
fi

if ! "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx postgres; then
  echo "postgres is not running — start the stack first (./docker-up.sh -d)." >&2
  exit 1
fi

DB_USER="$("${COMPOSE[@]}" exec -T postgres printenv POSTGRES_USER </dev/null | tr -d '\r')"
DB_NAME="$("${COMPOSE[@]}" exec -T postgres printenv POSTGRES_DB </dev/null | tr -d '\r')"

# The confirmation reads from the terminal, not stdin. stdin belongs to the
# dump being piped in, and consuming it here left the nested backup call with
# a closed stdin — which failed silently under `set -e` and aborted the whole
# restore *after* printing that it was about to run. Pass --yes to skip.
if [[ "${2:-}" != "--yes" ]]; then
  if [[ -r /dev/tty ]]; then
    echo "This replaces everything in '$DB_NAME' with the contents of $DUMP."
    read -r -p "Type the database name to confirm: " REPLY_NAME </dev/tty
    if [[ "$REPLY_NAME" != "$DB_NAME" ]]; then
      echo "Aborted — nothing changed."
      exit 1
    fi
  else
    echo "Not attached to a terminal. Re-run with --yes to confirm:" >&2
    echo "  ./scripts/db-restore.sh $DUMP --yes" >&2
    exit 1
  fi
fi

echo "Taking a safety dump of the current data first…"
./scripts/db-backup.sh pre-restore </dev/null

# --clean --if-exists drops each object before recreating it, so the restore
# is a replacement rather than a merge onto whatever is already there.
"${COMPOSE[@]}" exec -T postgres pg_restore -U "$DB_USER" -d "$DB_NAME" \
  --clean --if-exists --no-owner --no-privileges < "$DUMP"

echo "Restored $DUMP into '$DB_NAME'."
