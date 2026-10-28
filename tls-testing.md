# Testing `postgres-wire-proxy` against a TLS PostgreSQL

Every command and output in this file was run in this repository on 2026-10-28,
PostgreSQL 18.6.1 / psql 18.6.1 (`.pg/vendor/full/bin/psql`), on the `output-table`
branch. Exit codes are the ones psql actually returned. Start at step 1; each step
says what you must see before moving on.

Run everything from the repository root. Keep the proxy in its own terminal, so
`Ctrl-C` stops it and does not take psql with it.

---

## 1. Clean slate

```bash
scripts/postgres.sh stop
pgrep -af 'bin/postgres|postgres-wire-proxy' || echo "no server, no proxy"
ss -ltnp 2>/dev/null | grep -E ':(5432|5555)\b' || echo "ports free"
```

Expect `stopped` (or `not running`), `no server, no proxy`, `ports free`.

If a proxy is still there, kill it by pid: `pgrep -af postgres-wire-proxy`, then
`kill <pid>`. A proxy left over from an earlier attempt is the single most common
reason a later step "fails" for no visible reason — the port is answering, but it is
an old process with old flags.

---

## 2. Start PostgreSQL with TLS

```bash
scripts/postgres.sh start-ssl
```

Expect:

```
PostgreSQL 18.6.1 accepting connections on 127.0.0.1:5432
  ...
  ssl:     on, from .pg/tls
           proxy: --upstream-ca-cert .pg/tls/ca.crt
```

If a plaintext server was running, you also get one stderr line first:
`postgres.sh: restarting: the running server has ssl=off, not ssl=on`. That is the
script doing its job: a cluster keeps the flags it was started with.

Confirm:

```bash
scripts/postgres.sh status
```

Expect `ssl:  on` in the last line. On the very first run this step also creates a
private CA and a server certificate in `.pg/tls` (`ca.crt`, `ca.key`, `server.crt`,
`server.key`). It does not touch `postgresql.conf`; `ssl` is a command-line option,
so the file always reads `#ssl = off` even while the server serves TLS.

---

## 3. Prove the server itself speaks TLS (still no proxy)

```bash
PGPASSWORD=postgres .pg/vendor/full/bin/psql \
  "postgresql://postgres@127.0.0.1:5432/postgres?sslmode=require" \
  -tAc "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()"
```

Expect exactly:

```
t|TLSv1.3
```

`t` means the session is encrypted. If you get `f`, the server is not the one you
think it is — go back to step 2 and re-run `status`.

Note what this step does **not** prove: `ssl=on` makes the server offer TLS, it does
not require it. Plaintext still works directly:

```bash
PGPASSWORD=postgres .pg/vendor/full/bin/psql \
  "postgresql://postgres@127.0.0.1:5432/postgres?sslmode=disable" \
  -tAc "select 'plaintext-direct-ok'"
```

Expect `plaintext-direct-ok`. That is why the proxy's `--upstream-ssl-mode` flags
exist: the server will happily agree to plaintext if nobody insists on TLS.

---

## 4. Proxy with verified upstream TLS, plaintext client — expect a failure

Terminal A:

```bash
./target/debug/postgres-wire-proxy --port 5555 --upstream-port 5432 \
  --no-hex-dump --upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt
```

Expect:

```
... INFO  postgres_wire_proxy  PostgreSQL proxy listening on 127.0.0.1:5555 (non-SSL)
... INFO  postgres_wire_proxy  Forwarding to localhost:5432 (upstream SSL: require (verified))
```

(That `(non-SSL)` is the *client* side. The upstream line is what makes this
connection TLS.)

Terminal B:

```bash
PGPASSWORD=postgres .pg/vendor/full/bin/psql \
  "postgresql://postgres@127.0.0.1:5555/postgres?sslmode=disable" \
  -tAc "select 1"; echo "exit=$?"
```

Expect failure, exit 2:

```
psql: error: connection to server at "127.0.0.1", port 5555 failed:
server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection
exit=2
```

And in terminal A, in order:

```
Upstream SSL: sent SSLRequest
Upstream SSL: server agreed to TLS, handshaking (server name "localhost")
Upstream TLS handshake complete
```

**This is the important result, not a bug.** The upstream leg is TLS, so PostgreSQL
offers `SCRAM-SHA-256-PLUS` authentication, which binds the login to the certificate
the *client* was shown. Your client spoke plaintext to the proxy, so it refuses. The
proxy cannot fix this for you: it has to terminate TLS on the client side too, with a
certificate that produces the same channel binding.

---

## 5. The working setup: TLS on both legs

Stop the proxy from step 4 (`Ctrl-C` in terminal A), then restart it with client-side
TLS. The certificate **must be the one the server itself uses** (`.pg/tls/server.crt`),
not a different cert from the same CA — see 6.3 for what happens otherwise.

Terminal A:

```bash
./target/debug/postgres-wire-proxy --port 5555 --upstream-port 5432 \
  --table --table-dynamic-width --no-hex-dump \
  --upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt \
  --ssl-cert .pg/tls/server.crt --ssl-key .pg/tls/server.key
```

Expect `PostgreSQL proxy listening on 127.0.0.1:5555 (SSL enabled)` and
`Forwarding to localhost:5432 (upstream SSL: require (verified))`.

Terminal B:

```bash
PGPASSWORD=postgres .pg/vendor/full/bin/psql \
  "postgresql://postgres@127.0.0.1:5555/postgres?sslmode=verify-full&sslrootcert=$PWD/.pg/tls/ca.crt" \
  -tAc "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()"; echo "exit=$?"
```

Expect:

```
t|TLSv1.3
exit=0
```

Terminal A shows the full session: `Client requesting SSL`, the upstream handshake,
the protocol messages. `--table` / `--table-dynamic-width` change only what the
**proxy log** looks like; psql still prints ordinary results.

That is a complete round trip: client → TLS → proxy → TLS (verified) → PostgreSQL,
with channel binding satisfied.

---

## 6. Failure modes worth seeing on purpose

### 6.1 `require` without the CA — certificate rejected, connection dropped

Same as step 4 but drop `--upstream-ca-cert .pg/tls/ca.crt`:

```
ERROR  Connection error: Upstream TLS handshake failed: invalid peer certificate:
UnknownIssuer. If localhost:5432 uses a private CA, pass --upstream-ca-cert <pem>;
--upstream-tls-insecure skips verification; --upstream-ssl-mode=disable talks in plaintext
```

The client gets nothing useful:

```
psql: error: connection to server at "127.0.0.1", port 5555 failed:
server closed the connection unexpectedly
```

Learn to read this pair together: **"server closed the connection unexpectedly" in
psql means the proxy dropped you before PostgreSQL sent a single message.** The
reason is in the proxy log, never in the client. The server log will show
`could not accept SSL connection: tlsv1 alert unknown ca`.

### 6.2 Default `prefer` without the CA — silent-looking downgrade

Drop both TLS-related upstream flags:

```bash
./target/debug/postgres-wire-proxy --port 5555 --upstream-port 5432 --no-hex-dump
```

Connect as a plaintext client (`sslmode=disable`, step 4 command). The query
**succeeds** — this time the session is in the clear:

```
prefer-fell-back
exit=0
```

The proxy log carries the warning:

```
WARN  Upstream TLS handshake failed (invalid peer certificate: UnknownIssuer);
reconnecting in plaintext because --upstream-ssl-mode=prefer. Pass --upstream-ca-cert
<pem> to trust a private CA, --upstream-tls-insecure to skip verification, or
--upstream-ssl-mode=require to fail instead
INFO  Upstream SSL: falling back to plaintext
```

It works, and it is not encrypted. If a plaintext connection must never happen, use
`require`.

### 6.3 The wrong certificate for termination — login rejected

`.pg/tls/proxy.crt` is self-signed (`CN=127.0.0.1`), not issued by the test CA. Using
it for client-side TLS:

```bash
./target/debug/postgres-wire-proxy --port 5555 --upstream-port 5432 --no-hex-dump \
  --upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt \
  --ssl-cert .pg/tls/proxy.crt --ssl-key .pg/tls/proxy.key
```

```bash
PGPASSWORD=postgres .pg/vendor/full/bin/psql \
  "postgresql://postgres@127.0.0.1:5555/postgres?sslmode=verify-full&sslrootcert=$PWD/.pg/tls/proxy.crt" \
  -tAc "select 1"; echo "exit=$?"
```

```
psql: error: connection to server at "127.0.0.1", port 5555 failed:
FATAL:  SCRAM channel binding check failed
exit=2
```

The server says it plainly: `FATAL: SCRAM channel binding check failed`. Encryption
and verification are fine; the *binding* is wrong because the client hashed a
different certificate than the backend's.

### 6.4 Summary of the flag matrix

| upstream flags | client leg | result |
| --- | --- | --- |
| `--upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt` | plaintext | fails: `server offered SCRAM-SHA-256-PLUS ... over a non-SSL connection` |
| `--upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt --ssl-cert/--ssl-key .pg/tls/server.*` | `sslmode=verify-full` | works, `t|TLSv1.3` |
| `--upstream-ssl-mode=require` (no CA) | anything | `UnknownIssuer`, connection dropped |
| *(nothing: default `prefer`)* | plaintext | works in the clear, `WARN ... falling back to plaintext` |
| `--upstream-ssl-mode=require --upstream-ca-cert .pg/tls/ca.crt --ssl-cert/--ssl-key .pg/tls/proxy.*` | `verify-full` against `proxy.crt` | `FATAL: SCRAM channel binding check failed` |

---

## 7. Traps that cost time

- **`scripts/postgres.sh psql` never starts or restarts anything** (it used to). It
  connects to whatever is already listening on `PG_PORT` and fails with
  `postgres.sh: not running (start it with: ./scripts/postgres.sh start, or ... start-ssl)`
  if nothing is. Only `start` and `start-ssl` change the TLS mode, and `start` with
  `PG_SSL` unset still means `off` — so do not reach for plain `start` while you are
  testing TLS.

- **`--port` after the script's own flags wins.** `./scripts/postgres.sh psql --port 5555`
  connects to 5555, not `PG_PORT`: psql's later `--port` overrides the script's
  `-p 5432`. That is the proxy, not the server, so a connection failure there is a
  proxy problem, and the proxy log is where the reason is.

- **Two clocks.** `.pg/server.log` timestamps are in CET; the proxy logs UTC. The same
  moment appears one hour apart, so a 4-second restart looks impossible. Trust the
  pid, not the timestamps, when correlating: `scripts/postgres.sh status` prints the
  running pid, `postmaster.pid` line 1 does too.

- **`--upstream-ca-cert`, `--upstream-server-name` and `--upstream-tls-insecure` are
  rejected with `--upstream-ssl-mode=disable`** rather than ignored, so a leftover
  `disable` from plaintext testing will fail the proxy at startup.

- **`status` reads the running process, not the config.** `postgresql.conf` always
  says `#ssl = off`; only `show ssl` on a live connection is the truth.

---

## 8. Teardown

```bash
# Ctrl-C the proxy, then:
scripts/postgres.sh stop
scripts/postgres.sh status            # not running
pgrep -af 'bin/postgres|postgres-wire-proxy' || echo clean
```

`rm -rf .pg` throws away the cluster, the CA and the certificates; the next
`start-ssl` downloads the server and regenerates everything.
