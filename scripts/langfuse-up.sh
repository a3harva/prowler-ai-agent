#!/usr/bin/env bash
# Starts the Langfuse observability stack alongside the running application.
#
# Langfuse is behind a Compose profile, so it never starts with ./docker-up.sh
# or ./docker-watch.sh — start it here, when you are working on the agent, and
# stop it with ./scripts/langfuse-down.sh when you are not. That is not tidiness:
# Colima stays at 4 CPU / 8 GiB, and this stack is ~2.5 GiB of ceiling on top of
# an application stack that also has to fit a Prowler scanner container.
#
# Usage:
#   ./scripts/langfuse-up.sh          # start, wait for health, print the URL
#   ./scripts/langfuse-up.sh --pull   # pull newer images for the pinned tags first
set -euo pipefail
cd "$(dirname "$0")/.."

# ── Why all three compose files, every time ──────────────────────────────────
# Compose derives the project from the directory, so the Langfuse services land
# on the same network as api/worker either way — which is what lets them resolve
# `langfuse-web` by name. But invoking Compose with only the Langfuse file makes
# it consider every application container an orphan. It merely warns today; a
# future --remove-orphans (or a colleague adding one) would delete the running
# application stack. Listing all three files means there are no orphans to find.
COMPOSE=(docker compose
  -f docker-compose.yml
  -f docker-compose.local.yml
  -f docker-compose.langfuse.yml
  --env-file .env.local
  --profile langfuse)

if [[ ! -f .env.local ]]; then
  echo "error: .env.local not found — it supplies the API keys this stack seeds itself with." >&2
  exit 1
fi

# Langfuse requires a persistent 256-bit hex encryption key. Generate it once
# outside version control rather than shipping a functional default or asking
# operators to paste it into the public configuration contract.
LANGFUSE_KEY_FILE=".langfuse-encryption-key"
if [[ ! -f "$LANGFUSE_KEY_FILE" ]]; then
  umask 077
  openssl rand -hex 32 > "$LANGFUSE_KEY_FILE"
fi
LANGFUSE_ENCRYPTION_KEY="$(tr -d '\r\n' < "$LANGFUSE_KEY_FILE")"
if [[ ! "$LANGFUSE_ENCRYPTION_KEY" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: $LANGFUSE_KEY_FILE must contain exactly 64 lowercase hex characters." >&2
  exit 1
fi
export LANGFUSE_ENCRYPTION_KEY

# Generate the remaining Langfuse credentials once and keep them outside the
# repository. The file is deliberately shell-safe (hex values only), then
# validated before it is sourced and exported to Compose.
LANGFUSE_SECRETS_FILE=".langfuse-secrets"
LANGFUSE_SECRET_NAMES=(
  LANGFUSE_POSTGRES_PASSWORD
  LANGFUSE_REDIS_PASSWORD
  LANGFUSE_CLICKHOUSE_PASSWORD
  LANGFUSE_MINIO_ROOT_PASSWORD
  LANGFUSE_SALT
  LANGFUSE_NEXTAUTH_SECRET
  LANGFUSE_INIT_USER_PASSWORD
)
if [[ ! -f "$LANGFUSE_SECRETS_FILE" ]]; then
  umask 077
  : > "$LANGFUSE_SECRETS_FILE"
  for name in "${LANGFUSE_SECRET_NAMES[@]}"; do
    printf '%s=%s\n' "$name" "$(openssl rand -hex 32)" >> "$LANGFUSE_SECRETS_FILE"
  done
fi
while IFS='=' read -r name value; do
  if [[ ! " ${LANGFUSE_SECRET_NAMES[*]} " =~ " ${name} " ]] || \
     [[ ! "$value" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: $LANGFUSE_SECRETS_FILE contains an invalid credential entry." >&2
    exit 1
  fi
  export "$name=$value"
done < "$LANGFUSE_SECRETS_FILE"
for name in "${LANGFUSE_SECRET_NAMES[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "error: $LANGFUSE_SECRETS_FILE is missing $name." >&2
    exit 1
  fi
done

# The keys in .env.local and the keys Langfuse seeds itself with must be the
# same pair, or the SDK authenticates against a project that does not exist and
# every trace is silently rejected with a 401 nobody sees. Compose interpolates
# them from --env-file above; this only checks they are non-empty, and never
# prints them.
missing=()
for key in LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY; do
  if ! grep -qE "^${key}=.+" .env.local; then missing+=("$key"); fi
done
if (( ${#missing[@]} )); then
  echo "error: ${missing[*]} empty or absent in .env.local." >&2
  echo "       Empty keys mean tracing is disabled, which is a valid state — but then" >&2
  echo "       there is no reason to start this stack. Set both and re-run." >&2
  exit 1
fi

# ClickHouse merges clickhouse/langfuse-tuning.xml at boot, and a malformed
# file there is expensive to diagnose: the container restart-loops, the
# healthcheck reports only "connection refused", and the parse error appears
# on `docker logs` rather than in the server's own err log — which never gets
# written, because the server dies before opening it. Catch it here instead,
# in the second it takes.
#
# The specific trap that motivated this: **XML forbids `-` `-` inside a
# comment**, so a perfectly ordinary shell example pasted into an explanatory
# comment (any command with a long flag) silently makes the file unparseable.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse(sys.argv[1])" \
       clickhouse/langfuse-tuning.xml 2>/tmp/langfuse-xml-err; then
    echo "error: clickhouse/langfuse-tuning.xml is not valid XML — ClickHouse would" >&2
    echo "       restart-loop with only 'connection refused' to show for it." >&2
    sed 's/^/       /' /tmp/langfuse-xml-err >&2
    rm -f /tmp/langfuse-xml-err
    exit 1
  fi
  rm -f /tmp/langfuse-xml-err
fi

if [[ "${1:-}" == "--pull" ]]; then
  "${COMPOSE[@]}" pull langfuse-web langfuse-worker clickhouse minio langfuse-postgres langfuse-redis
fi

echo "Starting Langfuse (profile: langfuse) …"
"${COMPOSE[@]}" up -d langfuse-web

# ClickHouse migrations run on first boot and take a while; the web container is
# not useful until they finish. Poll rather than sleeping a guessed interval.
#
# **Poll `/`, not `/api/public/health`.** That endpoint does not exist on
# langfuse/langfuse:4.27.0 — it answers with Express's `Cannot GET /api/public/health`
# HTML, not the JSON "not available on deployments running in Langfuse v4
# events_only mode" that the read APIs return. So the probe could never succeed:
# every single run burned the full 180s and then printed the failure message
# below about ClickHouse being OOM-killed, while Langfuse was up and serving.
# A start script that always cries wolf is one whose output nobody reads.
#
# The trade-off in polling `/` instead: the app shell can answer a moment before
# ClickHouse has finished migrating. That is acceptable here and would not have
# been for a hard health check — the SDK is built per process and tolerates a
# collector that is not ready, so the cost of being early is a trace or two, and
# the cost of being wrong the other way was a scary message on every start.
echo -n "Waiting for langfuse-web to answer"
for _ in $(seq 1 90); do
  if curl -sf -o /dev/null http://localhost:3000/ 2>/dev/null; then
    echo
    echo
    echo "  Langfuse is up:  http://localhost:3000"
    echo "  Sign in with LANGFUSE_INIT_USER_EMAIL / _PASSWORD from docker-compose.langfuse.yml"
    echo "  The api and worker containers reach it at http://langfuse-web:3000 (LANGFUSE_HOST)."
    echo
    echo "  Tracing is on for any report generated from now on. Nothing needs restarting:"
    echo "  the client is built per process and tolerates the collector having been absent."
    exit 0
  fi
  echo -n "."
  sleep 2
done

echo
echo "langfuse-web did not become healthy within 180s." >&2
echo "First boot runs ClickHouse migrations and can legitimately be slow; check:" >&2
echo "  ${COMPOSE[*]} logs langfuse-web --tail 50" >&2
echo "  ${COMPOSE[*]} logs clickhouse --tail 50" >&2
echo >&2
echo "If ClickHouse was OOM-killed, that is the memory ceiling in" >&2
echo "clickhouse/langfuse-tuning.xml doing its job badly rather than a bug — it must" >&2
echo "stay BELOW the container's mem_limit, not above it." >&2
exit 1
