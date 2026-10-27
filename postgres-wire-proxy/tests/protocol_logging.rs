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

/// Read a whole startup packet: the 4-byte length, then the rest of the packet.
///
/// One `read` is not enough - the kernel is free to hand a packet over in
/// pieces - which is exactly what the proxy has to cope with too.
fn read_startup(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).expect("read startup length");
    let mut body = vec![0u8; u32::from_be_bytes(length) as usize - 4];
    stream.read_exact(&mut body).expect("read startup body");
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
