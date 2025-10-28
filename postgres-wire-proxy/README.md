# PostgreSQL Wire Protocol Proxy

A simple, transparent PostgreSQL wire protocol proxy written in Rust. This tool sits between a PostgreSQL client and server, logging all protocol messages in human-readable format while forwarding traffic bidirectionally.

## Features

- **Transparent Proxying**: One-to-one forwarding between client and upstream PostgreSQL server
- **Protocol Message Parsing**: Logs all PostgreSQL wire protocol messages in human-readable format
- **Hex Byte Dumps**: Every message includes a hex dump with offset, hex bytes, and ASCII representation
- **SSL Termination**: Optional SSL/TLS support for client connections
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
3. Forward decrypted traffic to upstream (non-SSL)
4. Log all decrypted protocol messages

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
  -h, --help                           Print help
  -V, --version                        Print version
```

## Example Log Output

Each protocol message is logged with both human-readable description and hex dump:

```
INFO postgres_wire_proxy: PostgreSQL proxy listening on 127.0.0.1:5466 (non-SSL)
INFO postgres_wire_proxy: Forwarding to localhost:5432
INFO postgres_wire_proxy: New connection from 127.0.0.1:54171
INFO postgres_wire_proxy: [127.0.0.1:54171] Client requesting SSL
INFO postgres_wire_proxy: [127.0.0.1:54171] SSL rejected (not configured)
INFO postgres_wire_proxy: [127.0.0.1:54171] Connecting to upstream localhost:5432
INFO postgres_wire_proxy: [127.0.0.1:54171] Connected to upstream
INFO postgres_wire_proxy: [127.0.0.1:54171] → Startup message (length: 8)

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← Authentication: AuthenticationOk
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 52 00 00 00 08 00 00 00 00                        R........

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← BackendKeyData
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 4b 00 00 00 0c 00 00 8c 2b f5 ae f8 8d            K.......+....

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← ReadyForQuery (idle)
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 5a 00 00 00 05 49                                 Z....I

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] → Query: SELECT 42 as answer;
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 51 00 00 00 19 53 45 4c 45 43 54 20 34 32 20 61   Q....SELECT 42 a
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0010: 73 20 61 6e 73 77 65 72 3b 00                     s answer;.

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← RowDescription (1 fields)
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 54 00 00 00 1f 00 01 61 6e 73 77 65 72 00 00 00   T......answer...
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0010: 00 00 00 00 00 00 00 17 00 04 ff ff ff ff 00 00   ................

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← DataRow (1 fields, 8 bytes)
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 44 00 00 00 0c 00 01 00 00 00 02 34 32            D..........42

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] ← CommandComplete: SELECT 1
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 43 00 00 00 0d 53 45 4c 45 43 54 20 31 00         C....SELECT 1.

INFO postgres_wire_proxy::protocol: [127.0.0.1:54171] → Terminate
INFO postgres_wire_proxy::protocol: [127.0.0.1:54171]   0000: 58 00 00 00 04                                    X....

INFO postgres_wire_proxy: [127.0.0.1:54171] Connection closed
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
5. Proxy forwards startup message to upstream
6. Proxy begins bidirectional message forwarding
7. All messages are parsed and logged in real-time
8. Connection closes when either side disconnects

## Testing

Connect through the proxy using any PostgreSQL client:

```bash
# Using psql
psql -h localhost -p 5466 -U myuser -d mydb

# Using connection string
psql "postgresql://myuser:mypass@localhost:5466/mydb"
```

## Notes

- The proxy creates a new upstream connection for each client connection (no connection pooling)
- Logs are written to stdout with ANSI colors and to file without colors
- SSL termination happens at the proxy; upstream connection is non-SSL
- The proxy does not modify any protocol messages, it only observes and logs them
