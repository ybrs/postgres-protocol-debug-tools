# PostgreSQL Wire Protocol Proxy

A simple, transparent PostgreSQL wire protocol proxy written in Rust. This tool sits between a PostgreSQL client and server, logging all protocol messages in human-readable format while forwarding traffic bidirectionally.

## Features

- **Transparent Proxying**: One-to-one forwarding between client and upstream PostgreSQL server
- **Protocol Message Parsing**: Logs all PostgreSQL wire protocol messages in human-readable format
- **Hex Byte Dumps**: Every message includes a hex dump with offset, hex bytes, and ASCII representation
- **SSL Termination**: Optional SSL/TLS support for client connections
- **Upstream TLS**: Optional TLS to the backend, `disable`/`prefer`/`require`, verified against the bundled Mozilla roots or a CA of your own
- **Table Mode**: Renders result sets as formatted tables, optionally sized to their content
- **Dual Logging**: Logs to both stdout and optional file simultaneously
- **Simple Text Format**: Easy-to-read log output without complexity
- **Configurable**: All parameters (ports, hosts, SSL) configurable via CLI

## Building

```bash
cargo build --release
```

The binary will be available at `target/release/postgres-wire-proxy`.

## Usage

### Basic Usage (Non-SSL)

```bash
./target/release/postgres-wire-proxy
```

This starts the proxy with defaults:
- Listen on: `127.0.0.1:5466`
- Forward to: `localhost:5432`
- No SSL
- Logs to stdout only

### With Custom Ports

```bash
./target/release/postgres-wire-proxy --port 5555 --upstream-port 5432
```

### With Log File

```bash
./target/release/postgres-wire-proxy --log-file proxy.log
```

Logs will be written to both stdout and the specified file.

### With SSL Termination

```bash
./target/release/postgres-wire-proxy \
  --ssl-cert /path/to/cert.pem \
  --ssl-key /path/to/key.pem \
  --port 5466
```

When SSL is configured, the proxy will:
1. Accept SSL connection requests from clients
2. Perform SSL handshake using the provided certificate
3. Forward decrypted traffic to upstream (in plaintext, unless the upstream is asked for TLS as well)
4. Log all decrypted protocol messages

### Upstream TLS

The proxy can also speak TLS to the backend. The default is what it always did:
ask the server, and carry on in plaintext if it says no.

```bash
# The backend requires TLS and its certificate is signed by a private CA
./target/release/postgres-wire-proxy --upstream-ca-cert /path/to/ca.pem

# Refuse to talk to a backend that will not do TLS
./target/release/postgres-wire-proxy --upstream-ssl-mode require

# Never ask
./target/release/postgres-wire-proxy --upstream-ssl-mode disable
```

How it behaves:

- The proxy sends the 8-byte `SSLRequest` and reads the server's one-byte answer,
  exactly as a client would, then wraps the socket in a rustls handshake. The
  proxy still reads plaintext on both sides, because it terminates rather than
  tunnels, so the log is unchanged.
- **Certificates are verified by default**, against the bundled Mozilla roots
  plus whatever `--upstream-ca-cert` adds, and the name is checked too:
  `--upstream-server-name` overrides the name verified and sent as SNI, for a
  backend reached by IP address or through a tunnel.
- `--upstream-tls-insecure` accepts any certificate, and warns at startup. That
  is encryption without authentication: for a server whose CA you cannot obtain.
- `prefer` falls back only on a refusal (`N`). A certificate failure - or a
  handshake that starts and fails - ends the connection; nothing is retried in
  the clear.
- `--upstream-ca-cert`, `--upstream-server-name` and `--upstream-tls-insecure`
  are rejected with `--upstream-ssl-mode disable` rather than silently ignored.

```
[127.0.0.1:54171] Connecting to upstream localhost:5432 (SSL: prefer (verified))
[127.0.0.1:54171] Upstream SSL: sent SSLRequest
[127.0.0.1:54171] Upstream SSL: server agreed to TLS, handshaking (server name "localhost")
[127.0.0.1:54171] Upstream TLS handshake complete
```

#### SCRAM channel binding through the proxy

Before pointing this at a server that requires both TLS and password
authentication, know this: once the backend connection is TLS, PostgreSQL offers
`SCRAM-SHA-256-PLUS`, and a client whose own connection to the proxy is plaintext
refuses it (psql 18.6, with the server offering both mechanisms):

```
psql: error: connection to server at "127.0.0.1", port 5466 failed:
server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection
```

Channel binding hashes the certificate the client was shown, so for the client to
satisfy it the proxy must present **the same certificate the backend does**, and
the client must reach the proxy over TLS:

```bash
./target/release/postgres-wire-proxy \
  --ssl-cert server.crt --ssl-key server.key \
  --upstream-ca-cert ca.pem
psql "postgresql://user@127.0.0.1:5466/db?sslmode=verify-full&sslrootcert=ca.pem"
```

With a certificate of its own the bindings differ, and the server rejects the
login with `FATAL: SCRAM channel binding check failed`. A backend using an
authentication method without channel binding avoids the whole issue.

[`scripts/postgres.sh`](../README.md#real-postgresql-for-manual-testing) sets
this up locally: `PG_SSL=on scripts/postgres.sh start` serves TLS from a CA it
generates for you.

### Table Mode

Enable table formatting for query results with the `--table` flag. Instead of showing individual DataRow messages, results are displayed in a formatted table:

```bash
./target/release/postgres-wire-proxy --table --port 5466 --upstream-port 5432
```

When table mode is enabled:
- **RowDescription** messages are still logged to show column metadata
- **DataRow** messages are rendered as formatted table rows with:
  - Column headers from RowDescription
  - Fixed-width columns: every column is 15 characters wide, whatever it holds
  - Unicode box-drawing characters for borders
  - Graceful truncation with ellipsis for values longer than a column

Example output with `--table`:
```
[127.0.0.1:57985] ← RowDescription (2 fields)
[127.0.0.1:57985]    Field 1: name='id', type=int4 (OID=23), format=binary
[127.0.0.1:57985]    Field 2: name='name', type=text (OID=25), format=binary
[127.0.0.1:57985] ┌───────────────┬───────────────┐
[127.0.0.1:57985] │id             │name           │
[127.0.0.1:57985] ├───────────────┼───────────────┤
[127.0.0.1:57985] │'1'            │'Alice'        │
[127.0.0.1:57985] │'2'            │'Bob'          │
[127.0.0.1:57985] │'3'            │'Charlie'      │
[127.0.0.1:57985] └───────────────┴───────────────┘
```

Table mode features:
- **Streaming**: Rows are printed as they arrive (no buffering)
- **Fixed-width columns**: Each column is 15 characters wide for consistent alignment
- **Automatic truncation**: Values longer than 15 characters are truncated with "..."
- **NULL handling**: NULL values are rendered as the text `NULL`
- **Multi-column support**: Handles any number of columns from the query

#### Dynamic column widths

`--table-dynamic-width` sizes each column to the widest thing in it - header or
value - instead of the fixed 15 characters, then caps the whole table to the
terminal width. It requires `--table`:

```bash
./target/release/postgres-wire-proxy --table --table-dynamic-width
```

```
[127.0.0.1:34910] ┌─────┬────────────────────┐
[127.0.0.1:34910] │id   │name                │
[127.0.0.1:34910] ├─────┼────────────────────┤
[127.0.0.1:34910] │'1'  │'Bob'               │
[127.0.0.1:34910] │'2'  │'a much longer name'│
[127.0.0.1:34910] │'3'  │'ünïcødé'           │
[127.0.0.1:34910] └─────┴────────────────────┘
```

The same query with `COLUMNS=20`, where the name column no longer fits:

```
[127.0.0.1:34918] ┌─────┬────────────┐
[127.0.0.1:34918] │id   │name        │
[127.0.0.1:34918] ├─────┼────────────┤
[127.0.0.1:34918] │'1'  │'Bob'       │
[127.0.0.1:34918] │'2'  │'a much l...│
[127.0.0.1:34918] │'3'  │'ünïcødé'   │
[127.0.0.1:34918] └─────┴────────────┘
```

How it behaves:
- No column is narrower than 5 characters, which holds a few characters plus the
  truncation ellipsis. When the terminal is too narrow to hold every column at
  that floor, the floor wins and the table is wider than the terminal.
- Over budget, the widest column is shaved one character at a time, so the
  columns that need the room keep it. Values that no longer fit are truncated
  with `...`.
- The cap is `$COLUMNS` when set, otherwise 120 when stdout is a terminal. If
  output is redirected - a log file, a pipe - there is no width to respect and
  columns keep their content width.
- **Rows are buffered**: the widest cell of a column is only known once the
  result set ends, so the table is printed when `CommandComplete` arrives. The
  default `--table` mode streams instead, and is better for large result sets.

### All Options

```
Options:
  -l, --listen <LISTEN>                Listen address [default: 127.0.0.1]
  -p, --port <PORT>                    Listen port [default: 5466]
      --upstream-host <UPSTREAM_HOST>  Upstream PostgreSQL host [default: localhost]
      --upstream-port <UPSTREAM_PORT>  Upstream PostgreSQL port [default: 5432]
      --ssl-cert <SSL_CERT>            SSL certificate file (enables SSL mode)
      --ssl-key <SSL_KEY>              SSL private key file (required if ssl-cert is provided)
      --log-file <LOG_FILE>            Log file path (optional, logs always go to stdout)
      --log-format <LOG_FORMAT>        Log format (full, short, bare) [default: full]
      --no-hex-dump                    Exclude hex dumps of wire data in logs
      --table                          Enable table formatting for DataRow output
      --table-dynamic-width            Size table columns to their content instead of
                                       the fixed 15 characters (requires --table)
      --upstream-ssl-mode <MODE>       How to ask the upstream for TLS: disable, prefer,
                                       require [default: prefer]
      --upstream-ca-cert <CA_CERT>     Extra CA certificate (PEM) to verify the upstream
                                       against. Added to the bundled Mozilla roots
      --upstream-server-name <NAME>    Name to verify the upstream certificate against
                                       and send as SNI [default: --upstream-host]
      --upstream-tls-insecure          Accept any upstream certificate: encrypt, but do
                                       not authenticate the server
  -h, --help                           Print help
  -V, --version                        Print version
```

## Example Log Output

Each protocol message is logged with both human-readable description and hex dump.
Shown here with `--log-format bare`, which leaves out the timestamp, level and
module prefix:

```
PostgreSQL proxy listening on 127.0.0.1:5466 (non-SSL)
Forwarding to localhost:5432
New connection from 127.0.0.1:54171
[127.0.0.1:54171] Client requesting SSL
[127.0.0.1:54171] SSL rejected (not configured)
[127.0.0.1:54171] Connecting to upstream localhost:5432
[127.0.0.1:54171] Connected to upstream
[127.0.0.1:54171] → Startup message (length: 104)

[127.0.0.1:54171] ← Authentication: AuthenticationOk
[127.0.0.1:54171]   0000: 52 00 00 00 08 00 00 00 00                        R........

[127.0.0.1:54171] ← BackendKeyData
[127.0.0.1:54171]   0000: 4b 00 00 00 0c 00 00 8c 2b f5 ae f8 8d            K.......+....

[127.0.0.1:54171] ← ReadyForQuery (idle)
[127.0.0.1:54171]   0000: 5a 00 00 00 05 49                                 Z....I

[127.0.0.1:54171] → Query: SELECT 42 as answer;
[127.0.0.1:54171]   0000: 51 00 00 00 19 53 45 4c 45 43 54 20 34 32 20 61   Q....SELECT 42 a
[127.0.0.1:54171]   0010: 73 20 61 6e 73 77 65 72 3b 00                     s answer;.

[127.0.0.1:54171] ← RowDescription (1 fields)
[127.0.0.1:54171]   0000: 54 00 00 00 1f 00 01 61 6e 73 77 65 72 00 00 00   T......answer...
[127.0.0.1:54171]   0010: 00 00 00 00 00 00 00 17 00 04 ff ff ff ff 00 00   ................

[127.0.0.1:54171] ← DataRow (1 fields, 8 bytes)
[127.0.0.1:54171]   0000: 44 00 00 00 0c 00 01 00 00 00 02 34 32            D..........42

[127.0.0.1:54171] ← CommandComplete: SELECT 1
[127.0.0.1:54171]   0000: 43 00 00 00 0d 53 45 4c 45 43 54 20 31 00         C....SELECT 1.

[127.0.0.1:54171] → Terminate
[127.0.0.1:54171]   0000: 58 00 00 00 04                                    X....

[127.0.0.1:54171] Connection closed (session 0.004s)
```

The hex dump format shows:
- Offset in hex (e.g., `0000:`, `0010:`)
- Hex bytes space-separated
- ASCII representation (non-printable chars shown as `.`)
```

## Supported Protocol Messages

The proxy recognizes and logs the following PostgreSQL wire protocol messages:

### Client → Server
- `Q` - Simple Query
- `P` - Parse (prepared statement)
- `B` - Bind
- `E` - Execute
- `D` - Describe
- `S` - Sync
- `X` - Terminate
- `p` - PasswordMessage
- `C` - Close
- `H` - Flush
- `d` - CopyData
- `c` - CopyDone
- `f` - CopyFail

### Server → Client
- `R` - Authentication
- `K` - BackendKeyData
- `Z` - ReadyForQuery
- `S` - ParameterStatus
- `T` - RowDescription
- `D` - DataRow
- `C` - CommandComplete
- `E` - ErrorResponse
- `N` - NoticeResponse
- `1` - ParseComplete
- `2` - BindComplete
- `3` - CloseComplete
- `n` - NoData
- `s` - PortalSuspended
- `t` - ParameterDescription
- `I` - EmptyQueryResponse
- `d` - CopyData
- `c` - CopyDone
- `G` - CopyInResponse
- `H` - CopyOutResponse
- `W` - CopyBothResponse

## Use Cases

- **Debugging PostgreSQL Client/Server Communication**: See exactly what queries and responses are being sent
- **Protocol Analysis**: Understand how PostgreSQL clients interact with servers
- **Testing**: Verify client behavior without inspecting network packets
- **Development**: Debug connection issues or protocol implementation
- **Learning**: Educational tool for understanding PostgreSQL wire protocol

## Connection Flow

1. Client connects to proxy
2. Proxy checks if client requests SSL
3. If SSL configured and requested, proxy performs SSL handshake
4. Proxy connects to upstream PostgreSQL server
5. Unless `--upstream-ssl-mode disable`, the proxy sends an `SSLRequest` and, if
the server agrees, performs a TLS handshake of its own with it
6. Proxy forwards startup message to upstream
7. Proxy begins bidirectional message forwarding
8. All messages are parsed and logged in real-time
9. Connection closes when either side disconnects

## Testing

Connect through the proxy using any PostgreSQL client:

```bash
# Using psql
psql -h localhost -p 5466 -U myuser -d mydb

# Using connection string
psql "postgresql://myuser:mypass@localhost:5466/mydb"
```

No server around? `scripts/postgres.sh start` from the repository root brings up a
rootless PostgreSQL 18 in `.pg/`; see
[Real PostgreSQL for manual testing](../README.md#real-postgresql-for-manual-testing).

## Notes

- Each client connection gets its own upstream connection, one to one, with no pooling: a client session and the upstream session it stands for stay the same thing, which is what makes the log a faithful trace of one session
- Logs are written to stdout with ANSI colors and to file without colors
- SSL termination happens at the proxy; the upstream connection follows `--upstream-ssl-mode`, so it is TLS when the server offers it and plaintext when it does not
- The proxy does not modify any protocol messages, it only observes and logs them
