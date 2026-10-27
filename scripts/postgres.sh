#!/usr/bin/env bash
# Run a real PostgreSQL server for manual testing against the proxy.
#
# No root and no system packages: a prebuilt PostgreSQL distribution (server and
# client, from https://github.com/theseus-rs/postgresql-binaries) is unpacked
# under .pg/ and the cluster is created beside it. Everything is project-local
# and gitignored.
#
#   scripts/postgres.sh start      # download + initdb + start, prints the URL
#   scripts/postgres.sh psql       # interactive psql against it
#   scripts/postgres.sh status
#   scripts/postgres.sh stop
#
# Environment: PG_PORT (default 5432, which is the proxy's default upstream
# port), PG_USER (postgres), PG_PASSWORD (postgres), PG_VERSION (18.6.1),
# PG_DIR (default .pg).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PG_VERSION=${PG_VERSION:-18.6.1}
PG_PORT=${PG_PORT:-5432}
PG_USER=${PG_USER:-postgres}
PG_PASSWORD=${PG_PASSWORD:-postgres}
PG_DIR=${PG_DIR:-$ROOT/.pg}
VENDOR="$PG_DIR/vendor/full"
DATA="$PG_DIR/data"
RUN="$PG_DIR/run"
LOG="$PG_DIR/server.log"

die() {
  echo "postgres.sh: $*" >&2
  exit 1
}

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) PLATFORM=x86_64-unknown-linux-gnu ;;
  Linux:aarch64) PLATFORM=aarch64-unknown-linux-gnu ;;
  Darwin:x86_64) PLATFORM=x86_64-apple-darwin ;;
  Darwin:arm64) PLATFORM=aarch64-apple-darwin ;;
  *) die "no prebuilt distribution for $(uname -s) $(uname -m)" ;;
esac

install_postgres() {
  if [ -x "$VENDOR/bin/postgres" ] && [ -x "$VENDOR/bin/psql" ]; then
    return 0
  fi
  command -v curl >/dev/null || die "curl is required to download PostgreSQL"

  local name="postgresql-$PG_VERSION-$PLATFORM.tar.gz"
  local url="https://github.com/theseus-rs/postgresql-binaries/releases/download/$PG_VERSION/$name"

  mkdir -p "$VENDOR"
  echo "downloading PostgreSQL $PG_VERSION ($PLATFORM, ~40 MB, one time)" >&2
  curl -fsSL "$url" -o "$VENDOR/$name"
  curl -fsSL "$url.sha256" -o "$VENDOR/$name.sha256"
  if command -v sha256sum >/dev/null; then
    (cd "$VENDOR" && sha256sum -c --quiet "$name.sha256") ||
      die "checksum mismatch for $name"
  elif command -v shasum >/dev/null; then
    (cd "$VENDOR" && shasum -a 256 -c "$name.sha256" >/dev/null) ||
      die "checksum mismatch for $name"
  else
    die "need sha256sum or shasum to verify the download"
  fi
  tar -xzf "$VENDOR/$name" -C "$VENDOR" --strip-components=1
  rm -f "$VENDOR/$name" "$VENDOR/$name.sha256"
}

init_cluster() {
  if [ -f "$DATA/PG_VERSION" ]; then
    return 0
  fi
  mkdir -p "$DATA" "$RUN"

  local pwfile="$PG_DIR/.pwfile"
  (umask 077 && printf '%s\n' "$PG_PASSWORD" >"$pwfile")
  # trust for the local socket (so the script needs no password plumbing),
  # scram-sha-256 over TCP: that is what a client through the proxy will use,
  # so AuthenticationSASL and the client's password message show up in the log.
  "$VENDOR/bin/initdb" -D "$DATA" \
    --username="$PG_USER" \
    --pwfile="$pwfile" \
    --auth-local=trust \
    --auth-host=scram-sha-256 \
    --encoding=UTF8 \
    --no-locale >/dev/null
  rm -f "$pwfile"
}

running() {
  [ -x "$VENDOR/bin/pg_ctl" ] && "$VENDOR/bin/pg_ctl" -D "$DATA" status >/dev/null 2>&1
}

start_quiet() {
  install_postgres
  init_cluster
  if running; then
    return 0
  fi
  mkdir -p "$RUN"
  # ssl stays off (the default): a client's SSLRequest gets 'N', which is the
  # proxy's plaintext path. Point psql at the proxy to exercise it.
  "$VENDOR/bin/pg_ctl" -D "$DATA" -l "$LOG" -w -t 60 \
    -o "-p $PG_PORT -k $RUN -c listen_addresses=127.0.0.1" start >/dev/null
}

url() {
  echo "postgresql://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT/postgres"
}

cmd_start() {
  start_quiet
  echo "PostgreSQL $PG_VERSION accepting connections on 127.0.0.1:$PG_PORT"
  echo "  data:    ${DATA#$ROOT/}"
  echo "  log:     ${LOG#$ROOT/}"
  echo "  psql:    $0 psql"
  echo "  direct:  psql \"$(url)\""
  echo "  via the proxy (port 5466): psql \"postgresql://$PG_USER:$PG_PASSWORD@127.0.0.1:5466/postgres\""
}

cmd_stop() {
  if running; then
    "$VENDOR/bin/pg_ctl" -D "$DATA" -w -t 60 stop -m fast >/dev/null
    echo "stopped"
  else
    echo "not running"
  fi
}

cmd_status() {
  if running; then
    "$VENDOR/bin/pg_isready" -h 127.0.0.1 -p "$PG_PORT"
    echo "data: ${DATA#$ROOT/}"
    echo "pid:  $(head -1 "$DATA/postmaster.pid")"
  else
    echo "not running"
    exit 1
  fi
}

cmd_psql() {
  start_quiet
  PGPASSWORD="$PG_PASSWORD" exec "$VENDOR/bin/psql" \
    -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d postgres "$@"
}

cmd_url() {
  url
}

cmd_help() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  echo
  echo "commands: start, stop, status, psql [args...], url"
}

case "${1:-help}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  psql)
    shift
    cmd_psql "$@"
    ;;
  url) cmd_url ;;
  help | -h | --help) cmd_help ;;
  *) die "unknown command '$1' (try: start, stop, status, psql, url)" ;;
esac
