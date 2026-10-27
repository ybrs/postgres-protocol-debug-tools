//! End-to-end tests for how the proxy decodes and logs wire protocol traffic.
//!
//! Each test runs the real `postgres-wire-proxy` binary against a fake upstream
//! that writes raw protocol bytes, drives a raw client through it, and asserts on
//! the proxy's log file. No PostgreSQL server is involved: the point is to
//! control exactly how the byte stream is chopped into reads, which is what the
//! decoder has to cope with.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a test waits for a line to show up in the proxy log.
const LOG_TIMEOUT: Duration = Duration::from_secs(5);

/// Used to give each spawned proxy its own temporary directory.
static NEXT_PROXY: AtomicUsize = AtomicUsize::new(0);

/// A running proxy binary, killed when the test finishes.
struct Proxy {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Proxy {
    fn start(upstream_port: u16, extra_args: &[&str]) -> Self {
        Self::start_with_env(upstream_port, extra_args, &[])
    }

    fn start_with_env(upstream_port: u16, extra_args: &[&str], envs: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "postgres-wire-proxy-test-{}-{}",
            std::process::id(),
            NEXT_PROXY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).expect("create test directory");

        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_postgres-wire-proxy"))
            .arg("--listen")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--upstream-host")
            .arg("127.0.0.1")
            .arg("--upstream-port")
            .arg(upstream_port.to_string())
            .arg("--log-file")
            .arg(dir.join("proxy.log"))
            // Bare format keeps log lines to `<client> <message>`, which makes
            // rendered table rows easy to compare with each other.
            .args(["--log-format", "bare"])
            .arg("--no-hex-dump")
            .args(extra_args)
            .envs(envs.iter().copied())
            // Logs also go to stdout; keep it off a pipe so a chatty session
            // cannot fill the pipe and block the proxy.
            .stdout(Stdio::from(File::create(dir.join("proxy.stdout")).unwrap()))
            .stderr(Stdio::from(File::create(dir.join("proxy.stderr")).unwrap()))
            .spawn()
            .expect("failed to start postgres-wire-proxy");

        let proxy = Self { child, port, dir };
        // Logged just before the accept loop starts.
        proxy.wait_for("listening on", LOG_TIMEOUT);
        proxy
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("proxy.log")).unwrap_or_default()
    }

    fn side_output(&self, name: &str) -> String {
        fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    /// Poll the log until it contains `needle`, panicking with the log contents
    /// if it never does.
    fn wait_for(&self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let log = self.log();
            if log.contains(needle) {
                return log;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?} in the proxy log\n\
                 --- proxy log ---\n{log}\n\
                 --- proxy stdout ---\n{}\n\
                 --- proxy stderr ---\n{}",
                self.side_output("proxy.stdout"),
                self.side_output("proxy.stderr"),
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A raw client connection, held open until it is dropped.
struct Client {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Client {
    fn connect(proxy_port: u16, query: Option<&str>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let query = query.map(str::to_string);

        let handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("client connect");
            stream.set_nodelay(true).unwrap();
            stream
                .write_all(&startup_message())
                .expect("write startup message");

            if let Some(query) = query {
                // A separate write, so the startup packet stays in its own read.
                thread::sleep(Duration::from_millis(100));
                stream
                    .write_all(&query_message(&query))
                    .expect("write query");
            }

            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut scratch = [0u8; 8192];
            while !stop_flag.load(Ordering::SeqCst) {
                match stream.read(&mut scratch) {
                    Ok(0) => break,
                    Ok(_) | Err(_) => {}
                }
            }
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start a fake PostgreSQL server that accepts one connection and runs `script`
/// with it. Returns the port it listens on.
fn spawn_upstream(script: impl FnOnce(&mut TcpStream) + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake upstream");
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fake upstream accept");
        stream.set_nodelay(true).unwrap();
        script(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    port
}

/// Protocol code a client sends to ask for TLS.
const SSL_REQUEST_CODE: u32 = 80877103;

/// Read the 8-byte packet the proxy opens with: an `SSLRequest`, or the start of
/// the startup packet. Returns its protocol code and its total length.
fn read_first_packet(stream: &mut TcpStream) -> (u32, usize) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut header = [0u8; 8];
    stream
        .read_exact(&mut header)
        .expect("read the proxy's first packet");

    (
        u32::from_be_bytes(header[4..8].try_into().unwrap()),
        u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize,
    )
}

fn read_packet_body(stream: &mut TcpStream, length: usize) {
    let mut body = vec![0u8; length - 8];
    stream.read_exact(&mut body).expect("read packet body");
}

/// Read a whole startup packet: the 4-byte length, then the rest of the packet.
///
/// One `read` is not enough - the kernel is free to hand a packet over in
/// pieces - which is exactly what the proxy has to cope with too.
///
/// The proxy asks for TLS before its startup packet, so the `SSLRequest` is
/// answered with 'N' first: that is what a server with `ssl = off` says, and it
/// is the path the default `--upstream-ssl-mode prefer` falls back on.
fn read_startup(stream: &mut TcpStream) {
    let (code, length) = read_first_packet(stream);
    if code == SSL_REQUEST_CODE {
        assert_eq!(length, 8, "an SSLRequest is 8 bytes");
        stream.write_all(b"N").expect("refuse SSL");
        stream.flush().unwrap();

        let (_, length) = read_first_packet(stream);
        read_packet_body(stream, length);
    } else {
        read_packet_body(stream, length);
    }
}

/// Read a startup packet and assert no `SSLRequest` came first, which is what
/// `--upstream-ssl-mode disable` has to look like on the wire.
fn read_startup_without_ssl(stream: &mut TcpStream) {
    let (code, length) = read_first_packet(stream);
    assert_eq!(code, 196_608, "expected the startup packet, not an SSLRequest");
    read_packet_body(stream, length);
}

/// Read one protocol message: the tag byte, the 4-byte length, then the body.
fn read_message(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("read message header");
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut body = vec![0u8; length - 4];
    stream.read_exact(&mut body).expect("read message body");
}

fn startup_message() -> Vec<u8> {
    let mut body = Vec::new();
    for parameter in ["user", "demo", "database", "demo"] {
        body.extend_from_slice(parameter.as_bytes());
        body.push(0);
    }
    body.push(0);

    let mut message = Vec::new();
    // Unlike a regular message there is no tag byte, so the length covers the
    // length field itself, the protocol version and the body.
    message.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    message.extend_from_slice(&196_608u32.to_be_bytes()); // protocol 3.0
    message.extend_from_slice(&body);
    message
}

fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn query_message(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    message(b'Q', &body)
}

/// RowDescription for `(name, type oid, format)` fields.
fn row_description(fields: &[(&str, u32, i16)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (name, type_oid, format) in fields {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&0u32.to_be_bytes()); // table oid
        body.extend_from_slice(&0u16.to_be_bytes()); // column attribute
        body.extend_from_slice(&type_oid.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes()); // type size
        body.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        body.extend_from_slice(&format.to_be_bytes());
    }
    message(b'T', &body)
}

fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for value in values {
        match value {
            Some(bytes) => {
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    message(b'D', &body)
}

fn command_complete(tag: &str) -> Vec<u8> {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    message(b'C', &body)
}

fn ready_for_query() -> Vec<u8> {
    message(b'Z', b"I")
}

/// The body length the proxy reports for a DataRow is its length field minus the
/// length field itself.
fn reported_row_bytes(row: &[u8]) -> usize {
    row.len() - 5
}

/// The rendered box lines of a table, with the `[client] ` log prefix removed.
fn box_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|line| line.split_once("] ").map(|(_, message)| message))
        .filter(|message| matches!(message.chars().next(), Some('┌' | '│' | '├' | '└')))
        .map(str::to_string)
        .collect()
}

/// A fake upstream that answers any query with `rows` under `fields`, then ends
/// the result set.
fn screenshot_upstream(
    fields: Vec<(&'static str, u32, i16)>,
    rows: Vec<Vec<Vec<u8>>>,
) -> u16 {
    spawn_upstream(move |stream| {
        read_startup(stream);
        read_message(stream);

        let mut batch = row_description(&fields);
        for row in &rows {
            let values: Vec<Option<&[u8]>> = row.iter().map(|v| Some(v.as_slice())).collect();
            batch.extend_from_slice(&data_row(&values));
        }
        batch.extend_from_slice(&command_complete(&format!("SELECT {}", rows.len())));
        batch.extend_from_slice(&ready_for_query());
        stream.write_all(&batch).unwrap();
        stream.flush().unwrap();
    })
}

// ---------------------------------------------------------------------------
// A TLS-capable fake upstream
// ---------------------------------------------------------------------------

/// The CA and server certificate the TLS tests use, generated once with openssl
/// (the same pair `scripts/postgres.sh` uses for its `ssl = on` local server).
/// The server key is a throwaway fixture that signs nothing but this certificate
/// and exists only so these tests need no certificate tooling.
const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUIduDa5pZ0Ohl8vnY1gLDGb5KSoMwCgYIKoZIzj0EAwIw
JjEkMCIGA1UEAwwbUG9zdGdyZXMgV2lyZSBQcm94eSBUZXN0IENBMB4XDTI2MTAy
NzE2MzQzMloXDTM2MTAyNDE2MzQzMlowJjEkMCIGA1UEAwwbUG9zdGdyZXMgV2ly
ZSBQcm94eSBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQ9jrjEK
DGSDceJHmUt3Kqg1EfsIZXKwRKyGCQujL51380ZPy1a8sAVWf1smjpqZVfCJ+bnW
hw/k92JG8BwfI6NTMFEwHQYDVR0OBBYEFAOOF/EPL17/odGsObzjJ0vBmYTGMB8G
A1UdIwQYMBaAFAOOF/EPL17/odGsObzjJ0vBmYTGMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIgHFbJQ6ILMS5mAtBWAoScil7CJPUnrJodpoi4GLi7
udsCIQCBGbzipoZe/D4b118NfHB7NdHhj412gke7VfJb3po/+Q==
-----END CERTIFICATE-----
";

const TEST_SERVER_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB0DCCAXWgAwIBAgIUSIwTnM2A/2Jcgjj+81zrTf+P5+YwCgYIKoZIzj0EAwIw
JjEkMCIGA1UEAwwbUG9zdGdyZXMgV2lyZSBQcm94eSBUZXN0IENBMB4XDTI2MTAy
NzE2MzQzMloXDTM2MTAyNDE2MzQzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM7Fs+UwQyFtgChzD6eeIl4qapxX0L3Mj
R4qnuBIe08l1CuixEYnM5vgpi8U7LJYvqs7YuJImXmffazB+5vVMiKOBkjCBjzAa
BgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8B
Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFAmlI/lGMiqb
IHwjNa2JVkSMcroRMB8GA1UdIwQYMBaAFAOOF/EPL17/odGsObzjJ0vBmYTGMAoG
CCqGSM49BAMCA0kAMEYCIQChS+ceqM7pPgIdPxnJzQZNzLvR8GPHGSK8417JiMiz
UwIhAMRL7MtiogQLi3C+0pV4mCKOoYSrAHF56HFxCkynHLz9
-----END CERTIFICATE-----
";

/// Throwaway, see above.
const TEST_SERVER_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3Bolmcbtd4ZQSMBK
7s5yAT4OidKKk+nCQ/Fhz8o5Vg2hRANCAAQzsWz5TBDIW2AKHMPp54iXipqnFfQv
cyNHiqe4Eh7TyXUK6LERiczm+CmLxTssli+qzti4kiZeZ99rMH7m9UyI
-----END PRIVATE KEY-----
";

/// Write the test CA out so the proxy can be pointed at it with
/// `--upstream-ca-cert`. The name keeps concurrent tests in one process off
/// each other's file.
fn write_ca_cert(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "postgres-wire-proxy-ca-{}-{name}.crt",
        std::process::id()
    ));
    fs::write(&path, TEST_CA_PEM).expect("write the test CA");
    path
}

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut TEST_SERVER_CERT_PEM.as_bytes())
            .collect::<Result<_, _>>()
            .expect("parse the test certificate");
    let key = rustls_pemfile::private_key(&mut TEST_SERVER_KEY_PEM.as_bytes())
        .expect("parse the test key")
        .expect("the test key is present");

    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("test TLS config"),
    )
}

/// A fake upstream that answers the `SSLRequest` with 'S' and completes a real
/// TLS handshake with the test certificate, then runs `script` on the decrypted
/// stream.
///
/// A proxy that refuses the certificate never gets this far: `accept` fails and
/// there is nothing to run, which is exactly what the verification tests want.
fn spawn_tls_upstream<F, Fut>(script: F) -> u16
where
    F: FnOnce(tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake upstream");
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fake upstream accept");
        stream.set_nodelay(true).unwrap();

        let (code, _) = read_first_packet(&mut stream);
        assert_eq!(code, SSL_REQUEST_CODE, "the proxy asks for TLS first");
        stream.write_all(b"S").expect("agree to TLS");
        stream.flush().unwrap();

        // `from_std` only takes a non-blocking socket; the SSLRequest above was
        // read with the socket still blocking.
        stream
            .set_nonblocking(true)
            .expect("the socket becomes non-blocking");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a test runtime");
        runtime.block_on(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_server_config());
            let stream = tokio::net::TcpStream::from_std(stream).expect("adopt the socket");
            if let Ok(tls) = acceptor.accept(stream).await {
                // Bounded, so a wedged session fails the waiting assertion
                // rather than hanging the test binary.
                let _ = tokio::time::timeout(Duration::from_secs(5), script(tls)).await;
            }
        });
    });

    port
}

async fn read_first_packet_async<S: AsyncReadExt + Unpin>(stream: &mut S) {
    let mut header = [0u8; 8];
    stream
        .read_exact(&mut header)
        .await
        .expect("read the proxy's first upstream packet");
    let length = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
    let mut body = vec![0u8; length - 8];
    stream
        .read_exact(&mut body)
        .await
        .expect("read the startup packet body");
}

async fn read_message_async<S: AsyncReadExt + Unpin>(stream: &mut S) {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .expect("read message header");
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut body = vec![0u8; length - 4];
    stream
        .read_exact(&mut body)
        .await
        .expect("read message body");
}

/// A one-row, one-column result set, as the TLS upstreams answer with.
fn single_row_response() -> Vec<u8> {
    let mut batch = row_description(&[("greeting", 25, 0)]);
    batch.extend_from_slice(&data_row(&[Some(b"encrypted")]));
    batch.extend_from_slice(&command_complete("SELECT 1"));
    batch.extend_from_slice(&ready_for_query());
    batch
}

#[test]
fn decodes_data_row_larger_than_the_read_buffer() {
    // A row big enough that it cannot possibly fit in one read of the proxy's
    // 8 KiB buffer: the decoder has to hold it until its last byte arrives.
    let payload = vec![b'x'; 20_000];
    let row = data_row(&[Some(b"1"), Some(payload.as_slice())]);
    let expected_body = reported_row_bytes(&row);

    let upstream_port = spawn_upstream(move |stream| {
        // Wait for the startup packet and the query: a response only makes
        // sense once the client has asked for something.
        read_startup(stream);
        read_message(stream);
        stream
            .write_all(&row_description(&[("id", 23, 0), ("payload", 25, 0)]))
            .unwrap();
        stream.flush().unwrap();
        // Keep the large row in a read of its own.
        thread::sleep(Duration::from_millis(150));

        let mut batch = row;
        batch.extend_from_slice(&command_complete("SELECT 1"));
        batch.extend_from_slice(&ready_for_query());
        stream.write_all(&batch).unwrap();
        stream.flush().unwrap();
    });

    let proxy = Proxy::start(upstream_port, &[]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    // CommandComplete is logged after the row, so waiting for it means the whole
    // response was decoded.
    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);

    assert!(
        log.contains("← RowDescription (2 fields)"),
        "missing RowDescription:\n{log}"
    );
    assert!(
        log.contains(&format!("← DataRow (2 fields, {expected_body} bytes)")),
        "missing the {expected_body}-byte DataRow:\n{log}"
    );
    assert!(
        log.contains(&format!("Value 2: '{}...' (20000 bytes)", "x".repeat(100))),
        "missing the payload value:\n{log}"
    );
}

#[test]
fn decodes_message_split_across_two_reads() {
    let value = "split across two reads";
    let row = data_row(&[Some(b"1"), Some(value.as_bytes())]);
    let expected_body = reported_row_bytes(&row);
    // Cut in the middle of the message body, where a read boundary can fall.
    let (head, tail) = row.split_at(12);
    let head = head.to_vec();
    let tail = tail.to_vec();

    let upstream_port = spawn_upstream(move |stream| {
        read_startup(stream);
        read_message(stream);
        stream.write_all(&head).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(150));

        let mut rest = tail;
        rest.extend_from_slice(&row_description(&[("id", 23, 0), ("name", 25, 0)]));
        rest.extend_from_slice(&command_complete("SELECT 1"));
        rest.extend_from_slice(&ready_for_query());
        stream.write_all(&rest).unwrap();
        stream.flush().unwrap();
    });

    let proxy = Proxy::start(upstream_port, &[]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);

    assert!(
        log.contains(&format!("← DataRow (2 fields, {expected_body} bytes)")),
        "the split DataRow ({expected_body} bytes) was not decoded:\n{log}"
    );
    assert!(
        log.contains(&format!(r"Value 2: '{value}'")),
        "the split value was not decoded:\n{log}"
    );
}

#[test]
fn table_mode_renders_fixed_width_rows_that_do_not_grow_with_content() {
    let long_value = "0123456789abcdefghij0123456789";
    let upstream_port = spawn_upstream(move |stream| {
        read_startup(stream);
        read_message(stream);
        let mut batch = row_description(&[("id", 23, 0), ("name", 25, 0)]);
        batch.extend_from_slice(&data_row(&[Some(b"1"), Some(b"Bob")]));
        batch.extend_from_slice(&data_row(&[Some(b"2"), Some(long_value.as_bytes())]));
        batch.extend_from_slice(&command_complete("SELECT 2"));
        batch.extend_from_slice(&ready_for_query());
        stream.write_all(&batch).unwrap();
        stream.flush().unwrap();
    });

    let proxy = Proxy::start(upstream_port, &["--table"]);
    let _client = Client::connect(proxy.port, Some("select * from demo"));

    // The table footer is printed when CommandComplete arrives, so waiting for
    // that line means every row has been rendered.
    let log = proxy.wait_for("← CommandComplete: SELECT 2", LOG_TIMEOUT);

    assert!(
        log.contains("→ Query: select * from demo"),
        "client query was not decoded:\n{log}"
    );
    // Every column is padded to the fixed 15 character width.
    let cell = |value: &str| format!("{value:<15}");
    for expected in [
        format!("│{}│{}│", cell("id"), cell("name")),
        format!("│{}│{}│", cell("'1'"), cell("'Bob'")),
        format!("│{}│{}│", cell("'2'"), cell("'0123456789a...")),
    ] {
        assert!(log.contains(&expected), "missing {expected:?}:\n{log}");
    }
    assert!(
        log.contains("┌─") && log.contains("└─"),
        "missing table borders:\n{log}"
    );

    // Every box line is the same width: two 15 character columns plus three
    // borders. A column that grew to fit its longest value would break this.
    let widths: Vec<usize> = log
        .lines()
        .filter_map(|line| line.split_once("] ").map(|(_, message)| message))
        .filter(|message| matches!(message.chars().next(), Some('┌' | '│' | '├' | '└')))
        .map(|message| message.chars().count())
        .collect();

    assert_eq!(
        widths.len(),
        6,
        "expected header, separator, two rows and a footer:\n{log}"
    );
    assert!(
        widths.iter().all(|width| *width == widths[0]),
        "box lines must all be the same width, got {widths:?}:\n{log}"
    );
    assert_eq!(widths[0], 33, "two 15 character columns plus three borders");
}

#[test]
fn table_dynamic_width_sizes_columns_to_their_content() {
    let upstream_port = screenshot_upstream(
        vec![("id", 23, 0), ("name", 25, 0)],
        vec![
            vec![b"1".to_vec(), b"Bob".to_vec()],
            vec![b"2".to_vec(), b"a much longer name".to_vec()],
        ],
    );

    let proxy = Proxy::start(upstream_port, &["--table", "--table-dynamic-width"]);
    let _client = Client::connect(proxy.port, Some("select * from demo"));
    let log = proxy.wait_for("← CommandComplete: SELECT 2", LOG_TIMEOUT);

    let lines = box_lines(&log);
    assert!(!lines.is_empty(), "no table was rendered:\n{log}");

    // `id` holds a 2 character header and 3 character values, so it sits at the
    // 5 character floor; `name` is as wide as its longest value instead of the
    // fixed 15, which is what keeps the long value intact.
    let expected_width = 1 + 5 + 1 + "'a much longer name'".len() + 1;
    for line in &lines {
        assert_eq!(
            line.chars().count(),
            expected_width,
            "column sized to its content, not 15: {line:?}\n{log}"
        );
    }
    assert!(
        log.contains("│'2'  │'a much longer name'│"),
        "the long value must not be truncated:\n{log}"
    );
    assert!(
        log.contains("│id   │name") || lines.iter().any(|line| line.starts_with("│id   ")),
        "the header is part of the column width:\n{log}"
    );
}

#[test]
fn table_dynamic_width_is_capped_to_the_terminal_width() {
    let long_value = "x".repeat(60);
    let upstream_port = screenshot_upstream(
        vec![("id", 23, 0), ("name", 25, 0)],
        vec![
            vec![b"1".to_vec(), b"Bob".to_vec()],
            vec![b"2".to_vec(), long_value.clone().into_bytes()],
        ],
    );

    let proxy = Proxy::start_with_env(
        upstream_port,
        &["--table", "--table-dynamic-width"],
        &[("COLUMNS", "40")],
    );
    let _client = Client::connect(proxy.port, Some("select * from demo"));
    let log = proxy.wait_for("← CommandComplete: SELECT 2", LOG_TIMEOUT);

    let lines = box_lines(&log);
    assert!(!lines.is_empty(), "no table was rendered:\n{log}");
    for line in &lines {
        assert_eq!(
            line.chars().count(),
            40,
            "the table must fit COLUMNS=40: {line:?}\n{log}"
        );
    }

    // The value no longer fits its column, so it is cut with an ellipsis rather
    // than wrapped or allowed to overflow.
    assert!(
        lines.iter().any(|line| line.ends_with("...│")),
        "the oversized value must be truncated:\n{log}"
    );
}

#[test]
fn table_dynamic_width_requires_table_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_postgres-wire-proxy"))
        .args(["--table-dynamic-width"])
        .output()
        .expect("run the proxy");

    assert!(!output.status.success(), "--table is required");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--table"),
        "the error should name the missing flag: {stderr}"
    );
}

#[test]
fn upstream_ssl_prefer_falls_back_to_plaintext_when_the_server_refuses() {
    let upstream_port = screenshot_upstream(vec![("id", 23, 0)], vec![vec![b"1".to_vec()]]);
    // `prefer` is the default; spelling it out pins that.
    let proxy = Proxy::start(upstream_port, &["--upstream-ssl-mode", "prefer"]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);
    assert!(log.contains("Upstream SSL: sent SSLRequest"), "{log}");
    assert!(
        log.contains("Upstream SSL: server refused TLS, continuing in plaintext"),
        "{log}"
    );
}

#[test]
fn upstream_ssl_disable_sends_no_ssl_request() {
    let upstream_port = spawn_upstream(|stream| {
        // An SSLRequest first would fail this assertion, which is the whole
        // point of `disable`.
        read_startup_without_ssl(stream);
        read_message(stream);
        stream.write_all(&single_row_response()).unwrap();
        stream.flush().unwrap();
    });

    let proxy = Proxy::start(upstream_port, &["--upstream-ssl-mode", "disable"]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);
    assert!(log.contains("Upstream SSL disabled"), "{log}");
    assert!(!log.contains("sent SSLRequest"), "{log}");
}

#[test]
fn upstream_ssl_require_fails_when_the_server_refuses() {
    let upstream_port = spawn_upstream(|stream| {
        let (code, _) = read_first_packet(stream);
        assert_eq!(code, SSL_REQUEST_CODE);
        stream.write_all(b"N").unwrap();
        stream.flush().unwrap();
        // Whatever the proxy does next, the test asserts on its log.
    });

    let proxy = Proxy::start(upstream_port, &["--upstream-ssl-mode", "require"]);
    let _client = Client::connect(proxy.port, None);

    let log = proxy.wait_for("Upstream refused TLS", LOG_TIMEOUT);
    assert!(
        !log.contains("→ Startup message"),
        "a refused TLS connection must not be carried on in plaintext:\n{log}"
    );
}

#[test]
fn upstream_tls_failure_is_not_retried_in_plaintext() {
    // A server that says 'S' and then speaks plaintext. The handshake cannot
    // succeed, and the proxy must not fall back to the clear.
    let upstream_port = spawn_upstream(|stream| {
        read_first_packet(stream);
        stream.write_all(b"S").unwrap();
        // Not a TLS record at all: an ErrorResponse, which is what a confused
        // server would send.
        stream.write_all(&message(b'E', b"SFATAL\x00")).unwrap();
        stream.flush().unwrap();
    });

    let proxy = Proxy::start(upstream_port, &[]);
    let _client = Client::connect(proxy.port, None);

    let log = proxy.wait_for("Upstream TLS handshake failed", LOG_TIMEOUT);
    assert!(!log.contains("→ Startup message"), "{log}");
}

#[test]
fn upstream_tls_verifies_the_server_against_the_given_ca() {
    let upstream_port = spawn_tls_upstream(|mut tls| async move {
        read_first_packet_async(&mut tls).await;
        read_message_async(&mut tls).await;
        tls.write_all(&single_row_response()).await.unwrap();
        tls.flush().await.unwrap();
    });
    let ca = write_ca_cert("verified");

    let proxy = Proxy::start(upstream_port, &["--upstream-ca-cert", ca.to_str().unwrap()]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);
    assert!(log.contains("Upstream TLS handshake complete"), "{log}");
    assert!(
        log.contains("Upstream SSL: server agreed to TLS"),
        "{log}"
    );
    assert!(
        log.contains("Value 1: 'encrypted'"),
        "the row must arrive over TLS:\n{log}"
    );
    assert!(!log.contains("Upstream SSL: server refused"), "{log}");
}

#[test]
fn upstream_tls_rejects_a_certificate_it_cannot_verify() {
    let upstream_port = spawn_tls_upstream(|mut tls| async move {
        // Unreachable: the proxy does not finish the handshake.
        read_first_packet_async(&mut tls).await;
    });

    // No --upstream-ca-cert. The test CA is not in the bundled Mozilla roots,
    // so verification has to fail; that is what makes the option meaningful.
    let proxy = Proxy::start(upstream_port, &[]);
    let _client = Client::connect(proxy.port, None);

    let log = proxy.wait_for("Upstream TLS handshake failed", LOG_TIMEOUT);
    // The reason has to be the certificate, not an unrelated failure: this is
    // the assertion that would catch a verifier that stopped verifying.
    assert!(
        log.contains("UnknownIssuer"),
        "expected the test CA to be untrusted, got:\n{log}"
    );
    assert!(!log.contains("→ Startup message"), "{log}");
}

#[test]
fn upstream_tls_insecure_accepts_an_untrusted_certificate() {
    let upstream_port = spawn_tls_upstream(|mut tls| async move {
        read_first_packet_async(&mut tls).await;
        read_message_async(&mut tls).await;
        tls.write_all(&single_row_response()).await.unwrap();
        tls.flush().await.unwrap();
    });

    let proxy = Proxy::start(upstream_port, &["--upstream-tls-insecure"]);
    let _client = Client::connect(proxy.port, Some("select 1"));

    let log = proxy.wait_for("← CommandComplete: SELECT 1", LOG_TIMEOUT);
    assert!(log.contains("Upstream SSL: server agreed to TLS"), "{log}");
    assert!(log.contains("verifying nothing"), "{log}");
    assert!(
        log.contains("certificate verification is off"),
        "the startup warning is missing:\n{log}"
    );
    assert!(log.contains("Value 1: 'encrypted'"), "{log}");
}

#[test]
fn upstream_tls_options_are_refused_with_disable() {
    let output = Command::new(env!("CARGO_BIN_EXE_postgres-wire-proxy"))
        .args(["--upstream-ssl-mode", "disable", "--upstream-tls-insecure"])
        .output()
        .expect("run the proxy");

    assert!(
        !output.status.success(),
        "--upstream-tls-insecure means nothing with --upstream-ssl-mode disable"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("have no effect"), "{stderr}");
}
