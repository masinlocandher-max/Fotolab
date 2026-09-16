#!/usr/bin/env bash
# Run the authorization suite. Exits non-zero on the first failed assertion, so
# it can gate a deploy directly.
#
#   ./tests/security/run.sh                      # ephemeral local Postgres
#   SCRATCH_DATABASE_URL=postgres://… ./run.sh   # a Supabase branch database
#
# Never point this at production. It writes fixtures, then rolls back.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [[ -n "${SCRATCH_DATABASE_URL:-}" ]]; then
  # A real Supabase branch already has auth.*, storage.* and the API roles.
  psql "$SCRATCH_DATABASE_URL" -v ON_ERROR_STOP=1 -f tests/security/authorization_tests.sql
  exit $?
fi

# Local mode: stand up a throwaway cluster, stub the Supabase-managed pieces,
# apply every migration, run the suite, tear down.
PGBIN=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | tail -1 || true)
[[ -n "$PGBIN" ]] && export PATH="$PGBIN:$PATH"
command -v initdb >/dev/null || { echo "postgres not installed; set SCRATCH_DATABASE_URL instead"; exit 2; }

DATADIR=$(mktemp -d)
PORT=${PGPORT_TEST:-55432}
SOCK=$(mktemp -d)
cleanup() { pg_ctl -D "$DATADIR" stop -m immediate >/dev/null 2>&1 || true; rm -rf "$DATADIR" "$SOCK"; }
trap cleanup EXIT

RUNAS=""
if [[ "$(id -u)" == "0" ]] && id postgres >/dev/null 2>&1; then
  chown postgres:postgres "$DATADIR" "$SOCK"; chmod o+rx "$SOCK"
  RUNAS="su postgres -c"
fi
run() { if [[ -n "$RUNAS" ]]; then su postgres -c "PATH=$PATH; $1"; else bash -c "$1"; fi; }

run "initdb -D $DATADIR -U postgres -A trust" >/dev/null
run "pg_ctl -D $DATADIR -o '-k $SOCK -p $PORT -c listen_addresses=' -w start" >/dev/null

PSQL="psql -h $SOCK -p $PORT -U postgres -v ON_ERROR_STOP=1"
$PSQL -q -f tests/security/supabase_stub.sql
for m in supabase/migrations/*.sql; do
  echo "applying $(basename "$m")"
  $PSQL -q -f "$m"
done
$PSQL -f tests/security/authorization_tests.sql
