#!/usr/bin/env bash
# Run a real PostgreSQL server for manual testing against the proxy.
#
# No root and no system packages: a prebuilt PostgreSQL distribution (server and
# client, from https://github.com/theseus-rs/postgresql-binaries) is unpacked
# under .pg/ and the cluster is created beside it. Everything is project-local
# and gitignored.
#
#   scripts/postgres.sh start      # download + initdb + start, prints the URL
#   scripts/postgres.sh start-ssl  # the same, with TLS on (same as PG_SSL=on start)
#   scripts/postgres.sh psql       # interactive psql against the running server
#   scripts/postgres.sh status
#   scripts/postgres.sh stop
#   scripts/postgres.sh tls        # generate a test CA and server certificate
#
# Environment: PG_PORT (default 5432, which is the proxy's default upstream
# port), PG_USER (postgres), PG_PASSWORD (postgres), PG_VERSION (18.6.1),
# PG_DIR (default .pg), PG_SSL (off; set to on to start the server with TLS,
# using .pg/tls and generating the certificates if they are not there yet).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PG_VERSION=${PG_VERSION:-18.6.1}
PG_PORT=${PG_PORT:-5432}
PG_USER=${PG_USER:-postgres}
PG_PASSWORD=${PG_PASSWORD:-postgres}
PG_DIR=${PG_DIR:-$ROOT/.pg}
PG_SSL=${PG_SSL:-off}
VENDOR="$PG_DIR/vendor/full"
DATA="$PG_DIR/data"
RUN="$PG_DIR/run"
LOG="$PG_DIR/server.log"
TLS="$PG_DIR/tls"

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

# What the *running* server has `ssl` set to, or nothing when it is not running.
# The cluster's postgresql.conf is never edited - ssl is a command-line option -
# so the file tells you nothing about the process that is actually serving.
running_ssl() {
  running || return 0
  "$VENDOR/bin/psql" -h "$RUN" -p "$PG_PORT" -U "$PG_USER" -d postgres \
    -tAc "show ssl" 2>/dev/null | tr -d '[:space:]'
}

# A private CA plus a server certificate for it, so PG_SSL=on is something the
# proxy can verify rather than only something it can talk to.
ensure_tls_certs() {
  if [ -f "$TLS/server.crt" ] && [ -f "$TLS/server.key" ]; then
    return 0
  fi
  command -v openssl >/dev/null || die "openssl is required to generate the TLS certificates"
  mkdir -p "$TLS"
  echo "generating a test CA and server certificate in ${TLS#$ROOT/}" >&2

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TLS/ca.key" -out "$TLS/ca.crt" -days 3650 -nodes \
    -subj "/CN=Postgres Wire Proxy Test CA" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TLS/server.key" -out "$TLS/server.csr" -nodes \
    -subj "/CN=localhost" 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
    >"$TLS/server.ext"
  openssl x509 -req -in "$TLS/server.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" \
    -CAcreateserial -out "$TLS/server.crt" -days 3650 -extfile "$TLS/server.ext" 2>/dev/null

  rm -f "$TLS/server.csr" "$TLS/server.ext" "$TLS/ca.srl"
  # The server refuses to start with a key anyone else can read.
  chmod 600 "$TLS/server.key" "$TLS/ca.key"
}

start_quiet() {
  install_postgres
  init_cluster

  local want=off
  [ "$PG_SSL" = on ] && want=on

  if running; then
    # A running cluster keeps the options it was started with, so "start" has
    # to mean "start with this TLS mode". Returning early here would leave a
    # server from an earlier `PG_SSL=on start` serving TLS while the caller
    # asked for plaintext - which looks exactly like the proxy failing to
    # connect to a server that "does not have TLS set up".
    local have
    have=$(running_ssl)
    if [ "$have" != "$want" ]; then
      echo "postgres.sh: restarting: the running server has ssl=${have:-?}, not ssl=$want" >&2
      "$VENDOR/bin/pg_ctl" -D "$DATA" -w -t 60 stop -m fast >/dev/null
    else
      return 0
    fi
  fi
  mkdir -p "$RUN"
  # With ssl off, a client's SSLRequest gets 'N', which is the proxy's plaintext
  # path. With PG_SSL=on the server wants TLS, which is what
  # --upstream-ssl-mode exercises; the certificate is signed by the CA in
  # .pg/tls, so --upstream-ca-cert has something to verify against and the
  # bundled roots deliberately do not.
  local options="-p $PG_PORT -k $RUN -c listen_addresses=127.0.0.1"
  if [ "$PG_SSL" = on ]; then
    ensure_tls_certs
    options="$options -c ssl=on -c ssl_cert_file=$TLS/server.crt -c ssl_key_file=$TLS/server.key"
  fi
  "$VENDOR/bin/pg_ctl" -D "$DATA" -l "$LOG" -w -t 60 -o "$options" start >/dev/null
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
  if [ "$PG_SSL" = on ]; then
    echo "  ssl:     on, from ${TLS#$ROOT/}"
    echo "           proxy: --upstream-ca-cert ${TLS#$ROOT/}/ca.crt"
  else
    echo "  ssl:     off (a client's SSLRequest is answered N)"
  fi
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
    echo "ssl:  $(running_ssl)"
  else
    echo "not running"
    exit 1
  fi
}

cmd_psql() {
  # Never starts the server: that would mean restarting a TLS server in plaintext
  # just because PG_SSL happens to be unset, which is the opposite of what "psql"
  # looks like it does.
  running || die "not running (start it with: $0 start, or $0 start-ssl)"
  PGPASSWORD="$PG_PASSWORD" exec "$VENDOR/bin/psql" \
    -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d postgres "$@"
}

cmd_url() {
  url
}

cmd_tls() {
  ensure_tls_certs
  chmod 600 "$TLS/server.key" "$TLS/ca.key"
  echo "  ca:      ${TLS#$ROOT/}/ca.crt"
  echo "  server:  ${TLS#$ROOT/}/server.crt"
}

cmd_help() {
  # The header comment block: everything after the shebang, up to the first
  # line that is not a comment.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
  echo
  echo "commands: start, start-ssl, stop, status, psql [args...], url, tls"
}

case "${1:-help}" in
  start) cmd_start ;;
  start-ssl)
    # Same as PG_SSL=on start, for when the TLS mode is not something to remember.
    PG_SSL=on
    cmd_start
    ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  psql)
    shift
    cmd_psql "$@"
    ;;
  url) cmd_url ;;
  tls) cmd_tls ;;
  help | -h | --help) cmd_help ;;
  *) die "unknown command '$1' (try: start, start-ssl, stop, status, psql, url, tls)" ;;
esac
