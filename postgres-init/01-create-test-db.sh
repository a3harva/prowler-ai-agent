#!/bin/sh
# The postgres image only auto-creates $POSTGRES_DB. The test suite needs a
# second, real database (TEST_DATABASE_URL) — SQLite is not a substitute
# because the schema uses JSONB and array types.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE ${POSTGRES_DB}_test'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${POSTGRES_DB}_test')\gexec
EOSQL
