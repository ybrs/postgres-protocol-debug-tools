# Findings: decoder framing, logging, and table mode

Notes from a review of `postgres-wire-proxy` on the `output-table` branch, plus the
answers to the numbered questions that came out of it. Written down because the
chat was getting long.

Everything marked **fixed** is in `postgres-wire-proxy/src/*.rs` and covered by
tests. Everything marked **open** is a known limitation that was deliberately not
changed.

## TL;DR

The decoder used to lose messages that did not arrive inside a single `read`.
That is not an edge case: any message larger than the 8 KiB read buffer is always
split, and so is any message that straddles a read boundary. The fix is a
persistent decode buffer in `parse_message`. Two further bugs surfaced while
testing it (a capped startup read, and two panics), both fixed. The table output
is and always was fixed-width; that is now pinned by tests. Four stale README
claims were corrected.

## 1. Bugs found and fixed

### 1.1 Messages split across reads were silently dropped — fixed

`main.rs` read once per loop iteration into a `BytesMut` that was cleared each
time, and passed only that slice to `parse_message`, which walks messages within
it and `break`s on the first incomplete one. Nothing was carried over. So:

- A message that arrived in two reads was lost: the first read ended mid-message
  and was dropped, the second read started mid-message and was mis-framed.
- **Any message larger than the read buffer was lost by construction.**
  `read_buf` can never return more than the buffer's spare capacity, so a
  20 KB `DataRow` (e.g. `SELECT repeat('x', 20000)`) always spans several reads.
  The decoder saw a length field exceeding the slice and gave up on every read
  that contained part of that row — including any *other* complete messages that
  happened to be in the same read behind it, since the loop breaks at the first
  bad frame.
- Re-synchronisation only happened by luck, when a later read boundary landed on
  a real message boundary.

Under TLS it is structural, not just likely: rustls hands over one TLS record at
a time, so a 20 KB row always arrives in several reads.

Fix: `parse_message` now consumes from a buffer that accumulates across reads.
Whole messages are decoded and removed from the front; a message whose last byte
has not arrived stays in the buffer for the next read. Forwarding is unchanged —
each read is still written to the peer before decoding, so the proxy stays
byte-accurate and cannot swallow data because of a decoder problem.

Related hardening in the same path:

- **Invalid length was a panic.** A length field below 4 sliced
  `buf[5..length + 1]` with an inverted range and panicked. A panic killed the
  pump task, and `select!` ignored the `JoinError`, so the connection died
  wearing a normal `Connection closed` line. Now such a byte is skipped
  byte-by-byte so the stream can re-sync, and a ~256 KiB run of garbage emits a
  warning instead of a wall of lines.
- **Unbounded buffering.** A message claiming a huge length would now be held
  forever. `MAX_DECODE_BUFFER` (16 MiB) bounds it: beyond that the buffer is
  dropped with a `warn!`, since a misread stream cannot be re-framed anyway.
- **Leftover bytes at end of connection** are logged as
  `N byte(s) in an incomplete trailing message` instead of disappearing.

### 1.2 The startup packet was read 8 bytes at a time — fixed

`handle_connection` used `BytesMut::with_capacity(8)` for its first read, so
`read_buf` returned at most 8 bytes: the proxy forwarded only the first 8 bytes
of the startup packet and fed the remainder to the decoder as if it were normal
messages. The log said `→ Startup message (length: 8)` for every session.

This was mostly cosmetic before — but with the persistent buffer it becomes
corrupting, because those stray startup bytes would sit at the head of the
decode buffer, every length read from them would be nonsense, and the connection
would never re-sync for its whole lifetime. It is a prerequisite for 1.1.

Fix: `read_startup_packet` reads the whole packet (validated 8…10000 bytes,
matching the server's own limit) and is shared by the plain and TLS paths. The
test log now shows the real size, e.g. `→ Startup message (length: 29)`.

### 1.3 Panic truncating multi-byte text — fixed

`parse_data_row` truncated long values with `&s[..100]`, which panics when a
multi-byte UTF-8 character straddles byte 100. A 200-byte UTF-8 value is enough
to kill the connection. Now truncated on a char boundary, with a regression test.

## 2. Tests added

`postgres-wire-proxy/tests/protocol_logging.rs` — end-to-end tests that run the
real binary (`CARGO_BIN_EXE_postgres-wire-proxy`) against a fake upstream writing
raw protocol bytes, drive a raw client through it, and assert on the proxy's log
file. No PostgreSQL server is involved; the point is to control exactly how the
byte stream is chopped into reads.

| Test | What it pins |
| --- | --- |
| `decodes_data_row_larger_than_the_read_buffer` | A 20 KB `DataRow` (plus the `CommandComplete` sharing its read) is decoded |
| `decodes_message_split_across_two_reads` | A `DataRow` cut mid-body across two writes is decoded |
| `table_mode_renders_fixed_width_rows_that_do_not_grow_with_content` | `--table` rendering, see §5.1 |

Unit tests were added alongside them: `protocol.rs` covers framing across
appends, an incomplete message staying buffered, and the multibyte truncation;
`table_formatter.rs` covers fixed widths.

The bug is genuinely pinned: with only the source fix stashed
(`git stash push postgres-wire-proxy/src`), `1 passed; 2 failed` — the two
framing tests fail, the table test (which is not about framing) passes.

The test harness itself had to be written carefully for the same reason the
proxy was broken: TCP has no message boundaries. An early version read the
startup packet with one `read`, got half of it, and desynced the fake upstream.
It also declared the startup length as `body.len() + 4` when a startup packet's
length field also covers the 4-byte protocol version, so the fake upstream read
one message's worth of the next packet. `read_startup` / `read_message` now read
whole packets.

## 3. Concurrent sessions in the log — what we can do (**open**)

Each protocol message emits several separate `info!` events, and all sessions
share one stdout sink, so a message's multi-line block can be interleaved with
another session's lines. Options, cheapest first:

1. **Leave it.** Every line carries `[addr:port]`, so any single line is
   attributable; only cross-line grouping is at risk.
2. **Per-session sinks.** Add a `{addr}` placeholder (or one file per session) to
   `--log-file`, so each session's trace is self-contained. Small change, all in
   `logging.rs`.
3. **Atomic message blocks.** Collect one message's lines into a single string
   and emit one event per message, or write under one lock. Requires
   restructuring the ~40 `info!` calls in `protocol.rs` into a per-message line
   collector, and it does not help across sessions unless the writer serialises
   too.

Recommendation: (1) unless logs are parsed programmatically; (2) if sessions
actually need to be correlated.

## 4. Upstream TLS — the plan, and where it was wrong (implemented, §11)

TLS used to be terminated for the client only; the proxy never sent an
`SSLRequest` upstream. To talk to a TLS-requiring server:

1. **Act as a TLS client upstream.** Send the 8-byte `SSLRequest` (code
   80877103), read the single `S`/`N` byte, and on `S` run a
   `rustls::ClientConfig` handshake over that same socket (tokio-rustls
   `TlsConnector`).
2. **Configuration.** A `ServerName` for SNI (default `--upstream-host`, with an
   override), and a trust source — rustls 0.23 ships no root certificates, so
   `webpki-roots` or `rustls-native-certs`, or a new `--upstream-ca-cert` for a
   private CA — plus a deliberate insecure escape hatch, since self-signed local
   servers are the common debugging case.
3. **Flags.** Something libpq-shaped, e.g.
   `--upstream-ssl-mode disable|prefer|require|verify-full`, defaulting to
   `prefer` (try `SSLRequest`, fall back to plaintext on `N`), which preserves
   today's behaviour by default.
4. **Plumbing.** `proxy_with_tcp` / `proxy_with_tls` and `run_proxy` hardcode
   `TcpStream` upstream and call `into_split()`; a TLS upstream means making that
   type generic or boxing it and using `tokio::io::split`.
5. What does not change: the proxy still logs plaintext, because it terminates
   rather than tunnels.

Three things in that plan did not survive contact:

- **No `verify-full` mode.** rustls verifies the hostname as part of verifying
  the certificate and has no `verify-ca` equivalent, so a separate mode would
  have promised something the other modes did not already do. Trust is therefore
  a property of the flags, not of the mode: verification is always on unless
  `--upstream-tls-insecure` says otherwise, and the mode only decides what
  happens when the server refuses. That also avoids libpq's trap of `require`
  being *weaker* than `prefer`.
- **`Box<dyn AsyncRead + AsyncWrite + Unpin + Send>` does not compile.** A trait
  object may carry only one non-auto trait. The fix is a one-line blanket trait
  (`trait UpstreamStream: AsyncRead + AsyncWrite + Unpin + Send {}`) and
  `Box<dyn UpstreamStream>`.
- **`proxy_with_tcp` and `proxy_with_tls` were the same function.** Threading
  another parameter through both would have meant writing it twice; they are now
  one `proxy_connection<C>`, generic over the client side.

What the plan did not anticipate at all — that authenticating through a
TLS-terminating proxy is a problem in its own right — is §11.

## 5. Answers to the specific questions

### 5.1 "Are you sure we don't have automatic column width?" — you do not, and never committed it

The git record is unambiguous: `table_formatter.rs` was added whole in the single
`--table format` commit (`d4dbb4c`, now history rather than HEAD), and every width-related line
in it is an addition. A dynamic-width version was never committed; the residue is
from something uncommitted:

```rust
terminal_width: None, // Not using dynamic width anymore
```

plus the now-unused `detect_terminal_width()`, `unicode_display_width()`
(referenced only by its own test), and the always-`None` `terminal_width` field.

Two tests now assert the current behaviour:

- unit: `rendered_rows_keep_their_width_when_values_are_long` — a short and a
  32-char value render identically wide, the cell is exactly `0123456789a...`,
  and `column_widths` stays `[15, 15]`.
- end-to-end: through the real binary, every `┌ │ ├ └` line in the log is 33
  characters (two 15-char columns plus three borders). A column that grew to fit
  its longest value would break that.

**Update:** content-sized columns now exist as an opt-in `--table-dynamic-width`
(§10). The fixed-width default and both tests above are unchanged, so they still
describe what you get without the flag.

### 5.2 The pump: nothing should be aborted

The earlier note that `run_proxy` "doesn't abort the other pump" was framed as a
defect. It is not. When the client dies:

- `run_proxy` spawns one task per direction and waits with `tokio::select!`.
  Pump A (client → upstream) gets EOF, logs `Client closed connection`, and ends
  → `select!` resolves → `run_proxy` logs `Connection closed (session …)` and
  returns.
- Dropping the loser's `JoinHandle` **detaches** the task; tokio does not cancel
  it. So pump B (upstream → client) keeps running, and anything the server sends
  afterwards **is still decoded and logged** — which is the desired behaviour and
  what happens today.
- Pump B ends on its own when the server closes, or when its next write to the
  dead client fails (`Failed to write to client: Broken pipe`).

Aborting would break exactly the behaviour that makes the tool useful. Genuine
issues in this area, none of them "don't abort":

- `Connection closed (session …)` is printed before the session truly ends, so
  lines can follow a "closed" line.
- **No read timeouts or keepalives (open).** A peer that disappears without a
  FIN (network drop) leaves a pump blocked in `read_buf` and its fd open
  indefinitely. A timeout is the fix, not an abort.
- The masking effect described in §1.1 — a decoder panic looking like a clean
  close — is now moot, because that panic is fixed.

### 5.3 The 1:1 connection model

Correct as designed, and now documented as intentional rather than apologised
for: each client connection gets its own upstream connection, no pooling, so a
client session and the upstream session it stands for stay the same thing. A
pooler would break the client ↔ backend correspondence that makes the log a
faithful trace of one session.

## 6. README drifts fixed

In `postgres-wire-proxy/README.md`:

- **Automatic column width** and **terminal width awareness** were listed as
  features of plain `--table`, which had neither. Removed; the accurate bullets
  ("Each column is fixed at 15 characters") already existed a few lines below,
  so the file contradicted itself in adjacent lines. Both are now documented
  where they belong, under the new `--table-dynamic-width` (§10).
- **Log example** showed the stock `tracing` prefix (`INFO postgres_wire_proxy:
  …`) instead of the custom formatter's `timestamp \t LEVEL \t target \t
  message`, and showed the stale `→ Startup message (length: 8)`. Now labelled
  and shown as `--log-format bare` (exactly reproducible) with `length: 104`, and
  the closing line corrected to `Connection closed (session 0.004s)`.
- **NULL handling**: "displayed as-is" actually means the literal text `NULL`,
  indistinguishable from a text column containing the word NULL.
- **1:1 connection note**: rewritten to state the rationale (§5.3) instead of
  reading as a missing feature.

The `docs/*.png` screenshots are current; only the text block was behind.

## 7. Deliberately left alone (**open**)

- **Cosmetic:** the mid-table separator uses `┬` instead of `┼` — `print_header`
  reuses `format_row`'s top border.
- **Dead code:** the width helpers that used to be dead are now used by
  `--table-dynamic-width` (§10); the remaining build warning is the
  never-read `FieldInfo::type_name`.
- **Formatting:** `cargo fmt --all` was not run. The repo has pre-existing
  rustfmt violations (module ordering in `main.rs`, several long calls), so
  reformatting would bury this change in unrelated churn. Only the new test file
  is formatted.
- **§3** is analysed but not implemented. **§4** is implemented (§11).

## 8. Verifying

```sh
cargo test --workspace        # 4 + 46 + 14 = 64 tests, exit 0
```

To see the framing bug for yourself, that the fix is what matters:

```sh
git stash push postgres-wire-proxy/src   # keep the new tests
cargo test -p postgres-wire-proxy
# 36 unit tests pass, upstream.rs not being compiled
# test result: FAILED. 6 passed; 8 failed
#   (the 2 framing tests, and every test that needs a flag added in §11)
git stash pop
```

The stash no longer isolates the framing bug: it takes the upstream TLS code with
it, so those tests fail on the removed flags too. One of them still passes,
because it asserts that a flag combination is *rejected* and an unrecognised flag
is rejected as well. Before this branch's second change set the same command gave
`1 passed; 2 failed`.

## 9. Manual verification against a real PostgreSQL server

`scripts/postgres.sh` brings up PostgreSQL 18.6.1 with no root and no system
packages: a prebuilt distribution from
[theseus-rs/postgresql-binaries](https://github.com/theseus-rs/postgresql-binaries)
is unpacked under `.pg/`, the cluster is created there, and the SHA-256 of the
download is verified. TCP auth is `scram-sha-256` (password `postgres`), the unix
socket is `trust`, and `ssl` is off, so a client's `SSLRequest` is answered `N`
and takes the proxy's plaintext path. `PG_SSL=on` serves TLS from a CA the script
generates instead; §11 is what uses that.

Verified with `psql` 18.6 through the proxy on `127.0.0.1:5466`, upstream
`127.0.0.1:5432`:

| Case | Observed |
| --- | --- |
| startup + SCRAM | `→ Startup message (length: 63)`, `← Authentication: AuthenticationSASL`, two `→ PasswordMessage`, `AuthenticationSASLFinal`, `AuthenticationOk` |
| simple query | `← RowDescription (2 fields)`, `← DataRow (2 fields, 16 bytes)`, `← CommandComplete: SELECT 1` |
| extended protocol (`\bind 21 \g`) | `→ Parse`/`Bind`/`Describe`/`Execute`/`Sync`, then `← ParseComplete`, `← BindComplete`, `← DataRow (1 fields, 8 bytes)` |
| `select repeat('x', 20000)` | `← DataRow (1 fields, 20006 bytes)`, value elided as `(20000 bytes)` |
| `select repeat('ä', 200)` | decoded, no panic; the pre-fix `&s[..100]` truncation would have died here |
| `select repeat('z', 5000000)` | `← DataRow (1 fields, 5000006 bytes)`, no incomplete-message warning |
| `--table`, 3 columns | fixed 15-character columns, `NULL` rendered literally, long value cut to `'a name long...` |

The client exited 0 every time and rows arrived intact, so forwarding stayed
byte-accurate. The `Upstream closed connection` line after `Connection closed` is
the detached sibling pump finishing (§5.2), not a second session.

## 10. `--table-dynamic-width`

Content-sized table columns, opt-in on top of `--table` (`clap` enforces the
pairing, so using it alone is an error naming the missing flag).

- Each column is as wide as the widest thing in it, header name or value, with a
  floor of 5 characters: a couple of characters plus the truncation ellipsis.
- The table is capped to the terminal: `$COLUMNS` when set, otherwise 120 when
  stdout is a terminal, and **no cap at all when output is redirected**, because
  a log file or a pipe has no width to respect. Over budget, the widest column is
  shaved one character at a time - so the columns that need the room keep it -
  down to the floor, and values that no longer fit are cut with `...`.
- Rows are buffered and the table is printed when `CommandComplete` arrives,
  since the widest cell of a column is only known once the result set ends.
  Plain `--table` still streams, so the default is unchanged for large results.

The dead `detect_terminal_width()`, `unicode_display_width()` and the
`terminal_width` field described in §5.1 are now what backs this, which is why the
build went from five warnings to one (the never-read `FieldInfo::type_name`).

Covered by unit tests in `table_formatter.rs` (content sizing, header sizing, the
floor, shrinking to a budget, truncation, equal-width rendered rows) and three
end-to-end tests through the real binary: content sizing, the `COLUMNS=40` cap,
and the `--table` requirement. Against the local PostgreSQL the same query
renders 28 characters wide uncapped and exactly 20 with `COLUMNS=20`, where the
long value becomes `'a much l...`.

## 11. Upstream TLS (`--upstream-ssl-mode` and friends)

`upstream.rs` is new; `main.rs` gained the flags and lost a duplicated function.

| Flag | Meaning |
| --- | --- |
| `--upstream-ssl-mode disable` | Never send an `SSLRequest` |
| `--upstream-ssl-mode prefer` | Ask; plaintext on `N` (default, as before) |
| `--upstream-ssl-mode require` | Ask; a refusal is a connection error |
| `--upstream-ca-cert <PEM>` | Trust anchor added to the bundled Mozilla roots |
| `--upstream-server-name <name>` | Name verified and sent as SNI (default `--upstream-host`) |
| `--upstream-tls-insecure` | Accept any certificate; warns at startup |

The three trust flags are refused with `--upstream-ssl-mode disable`, so an
option that cannot apply is an error rather than a silent no-op. Trust comes from
`webpki-roots` (new dependency) plus the CA file; `prefer` falls back only on an
`N`, and a failed handshake is never retried in the clear, which is the one place
this deliberately differs from libpq.

Tests: the negotiation cases run through the real binary against a fake upstream
that answers `N` (`prefer` fallback, `require` fails and forwards nothing, and
`disable` provably sends no `SSLRequest` at all, asserted on the first four bytes
on the wire), plus a server that answers `S` and then speaks plaintext. The
verification cases use a fake upstream that completes a real rustls handshake
with an embedded test certificate, which is what makes the pair meaningful: with
`--upstream-ca-cert` the session runs, and without it the handshake fails with
`UnknownIssuer` - asserted, so a verifier that stopped verifying would fail the
test rather than quietly pass it.

### Against the real server

`scripts/postgres.sh` gained `PG_SSL=on` and a `tls` command, generating a private
CA and a server certificate into `.pg/tls`. With PostgreSQL 18.6 on
`127.0.0.1:5432` and `psql` 18.6, `ssl` on, certificate signed by that CA:

| Configuration | Observed |
| --- | --- |
| default (`prefer`, verified), no CA | `Upstream TLS handshake failed: invalid peer certificate: UnknownIssuer` |
| `--upstream-ca-cert .pg/tls/ca.crt` | `Upstream TLS handshake complete` |
| `--upstream-tls-insecure` | handshake completes, `verifying nothing` warned at startup |
| `--upstream-server-name localhost` + CA | handshake completes (the certificate carries `DNS:localhost` and `IP:127.0.0.1`) |
| `--upstream-server-name wrong.example.com` + CA | `certificate not valid for name "wrong.example.com"; certificate is only valid for DnsName("localhost") or IpAddress(127.0.0.1)` |
| `--upstream-ssl-mode disable` | works; `pg_stat_ssl.ssl` for the upstream session is `f` |
| `--upstream-ssl-mode require`, server `ssl = off` | `Upstream refused TLS, but --upstream-ssl-mode=require` |
| default, server `ssl = off` | `Upstream SSL: server refused TLS, continuing in plaintext` |
| client TLS + same cert as the server + CA | `1\|hi\|t\|TLSv1.3` - the query ran, and the upstream session is TLS |
| client TLS + a different cert | `FATAL: SCRAM channel binding check failed` |

In the working TLS sessions a 20 000-byte value came back intact, with zero
`incomplete` warnings, and `--table --table-dynamic-width` rendered it - the same
framing path §1.1 fixed, now over TLS records, where the split is structural.

### What it exposed: channel binding

An upstream on TLS makes PostgreSQL offer `SCRAM-SHA-256-PLUS`. The hex dump of
the `AuthenticationSASL` message shows the server offering both mechanisms
(`SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0`), yet psql 18.6 fails anyway when its own
connection to the proxy is plaintext:

```
server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection
```

`channel_binding=disable` did not avoid it, as a URI parameter or as
`PGCHANNELBINDING`. Since channel binding hashes the certificate the client was
shown, the client passes only when the proxy presents the same certificate the
backend does and the client reaches the proxy over TLS; a different certificate
produces `FATAL: SCRAM channel binding check failed` instead. Both are verified
above. It is a property of terminating TLS in front of SCRAM, not of this
implementation - but it is the first thing a user hits, so it is in both READMEs.
