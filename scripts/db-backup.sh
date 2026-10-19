#!/usr/bin/env bash
# Dumps the local database to ./backups/ as a compressed custom-format archive.
#
# The bind mount at ./postgres-data survives container recreation, volume
# pruning and a Colima reset — but it does not survive `rm -rf`, a bad
# migration, or a mistaken `docker-down.sh --volumes`. This is the answer to
# those. It is cheap; run it before anything you are unsure about.
#
# Usage:
#   ./scripts/db-backup.sh              # timestamped dump
#   ./scripts/db-backup.sh before-migration   # add a label to the filename
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)

if ! "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx postgres; then
  echo "postgres is not running — start the stack first (./docker-up.sh -d)." >&2
  exit 1
fi

mkdir -p backups

# </dev/null throughout: `compose exec -T` otherwise inherits and consumes the
# caller's stdin, which breaks this script when it is invoked from inside
# another one that is itself being piped a dump.
DB_USER="$("${COMPOSE[@]}" exec -T postgres printenv POSTGRES_USER </dev/null | tr -d '\r')"
DB_NAME="$("${COMPOSE[@]}" exec -T postgres printenv POSTGRES_DB </dev/null | tr -d '\r')"

LABEL="${1:-}"
[[ -n "$LABEL" ]] && LABEL="-${LABEL//[^A-Za-z0-9_-]/-}"
OUT="backups/${DB_NAME}-$(date +%Y%m%d-%H%M%S)${LABEL}.dump"

# Custom format (-Fc): compressed, and restorable selectively with pg_restore.
"${COMPOSE[@]}" exec -T postgres pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$OUT"

echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "Restore with: ./scripts/db-restore.sh $OUT"
