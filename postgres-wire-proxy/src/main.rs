use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::{ArgAction, Parser};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

mod table_formatter;
mod protocol;
use protocol::{format_duration, parse_message, ClientState, ConnectionTiming, MessageDirection};
mod logging;
use logging::{setup_logging, LogFormat};
mod upstream;
use upstream::{BoxedUpstream, UpstreamSsl, UpstreamSslMode};

#[derive(Parser, Debug)]
#[command(author, version, about = "PostgreSQL wire protocol proxy", long_about = None)]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "127.0.0.1")]
    listen: String,

    /// Listen port
    #[arg(short, long, default_value = "5466")]
    port: u16,

    /// Upstream PostgreSQL host
    #[arg(long, default_value = "localhost")]
    upstream_host: String,

    /// Upstream PostgreSQL port
    #[arg(long, default_value = "5432")]
    upstream_port: u16,

    /// SSL certificate file (enables SSL mode)
    #[arg(long)]
    ssl_cert: Option<PathBuf>,

    /// SSL private key file (required if ssl-cert is provided)
    #[arg(long)]
    ssl_key: Option<PathBuf>,

    /// Log file path (optional, logs always go to stdout)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Log format (full, short, bare)
    /// Full: Timestamp, Level, Target/Module, ClientIP:Port, Message
    /// Short: Timestamp, ClientIP:Port, Message
    /// Bare: Client IP:Port, Message
    #[arg(long, value_enum, default_value_t = LogFormat::Full)]
    log_format: LogFormat,

    /// hex-dump/no-hex-dump: Include/Exclude hex dumps of wire data in logs,
    #[arg(long = "hex-dump", action = ArgAction::SetTrue, default_value_t = true)]
    #[arg(long = "no-hex-dump", action = ArgAction::SetFalse)]
    hex_dump: bool,

    /// Enable table formatting for DataRow output
    #[arg(long)]
    table: bool,

    /// Size table columns to their content instead of the fixed 15 characters.
    /// Rows are held back until the result set finishes, and the table is capped
    /// to the terminal width (or $COLUMNS)
    #[arg(long, requires = "table")]
    table_dynamic_width: bool,

    /// How to ask the upstream for TLS: disable, prefer, require.
    /// disable: never ask. prefer: ask, carry on in plaintext if refused.
    /// require: ask, and treat a refusal as a connection error
    #[arg(long, value_enum, default_value_t = UpstreamSslMode::default())]
    upstream_ssl_mode: UpstreamSslMode,

    /// Extra CA certificate (PEM) to verify the upstream against, for a private
    /// or self-signed CA. Added to the bundled Mozilla roots
    #[arg(long)]
    upstream_ca_cert: Option<PathBuf>,

    /// Name to verify the upstream certificate against and send as SNI.
    /// Defaults to --upstream-host
    #[arg(long)]
    upstream_server_name: Option<String>,

    /// Accept any upstream certificate: encrypt, but do not authenticate the
    /// server. For debugging against a server you cannot add a CA for
    #[arg(long)]
    upstream_tls_insecure: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    setup_logging(args.log_file.as_ref(), args.log_format)?;

    // These only mean something once there is TLS to configure; silently
    // ignoring them would look like they had been applied.
    if args.upstream_ssl_mode == UpstreamSslMode::Disable
        && (args.upstream_ca_cert.is_some()
            || args.upstream_server_name.is_some()
            || args.upstream_tls_insecure)
    {
        anyhow::bail!(
            "--upstream-ca-cert, --upstream-server-name and --upstream-tls-insecure have no \
             effect with --upstream-ssl-mode disable"
        );
    }

    let upstream_ssl = UpstreamSsl {
        mode: args.upstream_ssl_mode,
        ca_cert: args.upstream_ca_cert.clone(),
        server_name: args.upstream_server_name.clone(),
        insecure: args.upstream_tls_insecure,
    };
    if upstream_ssl.insecure && upstream_ssl.mode != UpstreamSslMode::Disable {
        warn!(
            "Upstream TLS certificate verification is off (--upstream-tls-insecure); \
             the connection is encrypted but the server is not authenticated"
        );
    }

    // Validate SSL configuration
    let ssl_config = if let Some(cert_path) = &args.ssl_cert {
        let key_path = args
            .ssl_key
            .as_ref()
            .context("ssl-key is required when ssl-cert is provided")?;
        Some(load_ssl_config(cert_path, key_path)?)
    } else {
        None
    };

    let listen_addr = format!("{}:{}", args.listen, args.port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .context("Failed to bind to listen address")?;

    if ssl_config.is_some() {
        info!(
            "PostgreSQL proxy listening on {} (SSL enabled)",
            listen_addr
        );
    } else {
        info!("PostgreSQL proxy listening on {} (non-SSL)", listen_addr);
    }
    info!(
        "Forwarding to {}:{} (upstream SSL: {})",
        args.upstream_host,
        args.upstream_port,
        upstream_ssl.describe()
    );
    let hex_dump = args.hex_dump;
    let table_mode = args.table;
    let table_dynamic_width = args.table_dynamic_width;

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("New connection from {}", client_addr);

        let upstream_host = args.upstream_host.clone();
        let upstream_port = args.upstream_port;
        let ssl_config = ssl_config.clone();
        let upstream_ssl = upstream_ssl.clone();
        let hex_dump = hex_dump;
        let table_mode = table_mode;
        let table_dynamic_width = table_dynamic_width;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                client_socket,
                client_addr.to_string(),
                upstream_host,
                upstream_port,
                ssl_config,
                upstream_ssl,
                hex_dump,
                table_mode,
                table_dynamic_width,
            )
            .await
            {
                error!("Connection error: {:#}", e);
            }
        });
    }
}

fn load_ssl_config(cert_path: &PathBuf, key_path: &PathBuf) -> Result<Arc<rustls::ServerConfig>> {
    let cert_file = File::open(cert_path).context("Failed to open certificate file")?;
    let key_file = File::open(key_path).context("Failed to open key file")?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate")?;

    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create SSL config")?;

    Ok(Arc::new(config))
}

/// Length the server itself accepts for a startup packet; also stops a bogus
/// length from allocating an enormous buffer.
const MAX_STARTUP_PACKET_LENGTH: usize = 10_000;

/// Read one startup packet: the 4-byte length, the 4-byte protocol version (or
/// SSL request code) and the body that follows.
///
/// The whole packet is read rather than however many bytes one read returns, so
/// that no startup bytes are left behind for the message decoder to mistake for
/// protocol messages. Returns `None` when the peer went away or sent a length
/// that cannot be a startup packet.
async fn read_startup_packet<S>(stream: &mut S, client_addr: &str) -> Result<Option<BytesMut>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    if let Err(e) = stream.read_exact(&mut header).await {
        warn!("[{}] Client disconnected during startup: {}", client_addr, e);
        return Ok(None);
    }

    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(8..=MAX_STARTUP_PACKET_LENGTH).contains(&length) {
        warn!("[{}] Invalid startup packet length {}", client_addr, length);
        return Ok(None);
    }

    let mut packet = BytesMut::with_capacity(length);
    packet.extend_from_slice(&header);
    if length > 8 {
        packet.resize(length, 0);
        stream
            .read_exact(&mut packet[8..length])
            .await
            .context("Failed to read startup packet body")?;
    }

    Ok(Some(packet))
}

/// Report bytes that never completed a protocol message, so a truncated stream
/// shows up in the log instead of silently missing from it.
fn log_undecoded(buf: &BytesMut, client_addr: &str) {
    if !buf.is_empty() {
        info!(
            "[{}] {} byte(s) in an incomplete trailing message",
            client_addr,
            buf.len()
        );
    }
}

async fn handle_connection(
    mut client_socket: TcpStream,
    client_addr: String,
    upstream_host: String,
    upstream_port: u16,
    ssl_config: Option<Arc<rustls::ServerConfig>>,
    upstream_ssl: UpstreamSsl,
    hex_dump: bool,
    table_mode: bool,
    table_dynamic_width: bool,
) -> Result<()> {
    // Read the startup packet whole. Leaving part of it in the socket would hand
    // startup bytes to the message decoder, which would read them as protocol
    // messages and lose the framing of everything that follows.
    let Some(startup_packet) = read_startup_packet(&mut client_socket, &client_addr).await? else {
        return Ok(());
    };

    let protocol = u32::from_be_bytes([
        startup_packet[4],
        startup_packet[5],
        startup_packet[6],
        startup_packet[7],
    ]);

    if protocol == upstream::SSL_REQUEST_CODE {
        info!("[{}] Client requesting SSL", client_addr);

        if let Some(config) = ssl_config {
            // Accept SSL
            client_socket.write_all(&[b'S']).await?;
            info!("[{}] SSL accepted, performing handshake", client_addr);

            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            let mut tls_stream = acceptor
                .accept(client_socket)
                .await
                .context("SSL handshake failed")?;

            info!("[{}] SSL handshake complete", client_addr);

            // The client sends the real startup packet over TLS next.
            let Some(startup_buf) = read_startup_packet(&mut tls_stream, &client_addr).await?
            else {
                return Ok(());
            };

            // Connect to upstream and proxy with the decrypted client stream
            return proxy_connection(
                tls_stream,
                startup_buf,
                client_addr,
                upstream_host,
                upstream_port,
                upstream_ssl,
                hex_dump,
                table_mode,
                table_dynamic_width,
            )
            .await;
        } else {
            // Reject SSL
            client_socket.write_all(&[b'N']).await?;
            info!("[{}] SSL rejected (not configured)", client_addr);

            // The SSL request carries no body of its own, so the real startup
            // packet follows in the clear.
            let Some(startup_buf) = read_startup_packet(&mut client_socket, &client_addr).await?
            else {
                return Ok(());
            };

            return proxy_connection(
                client_socket,
                startup_buf,
                client_addr,
                upstream_host,
                upstream_port,
                upstream_ssl,
                hex_dump,
                table_mode,
                table_dynamic_width,
            )
            .await;
        }
    }

    // Non-SSL path: what was read is the startup packet itself.
    proxy_connection(
        client_socket,
        startup_packet,
        client_addr,
        upstream_host,
        upstream_port,
        upstream_ssl,
        hex_dump,
        table_mode,
        table_dynamic_width,
    )
    .await
}

/// Connect to the backend and pump messages both ways. Generic over the client
/// side, so the plaintext client and the TLS-terminated client share one path;
/// the upstream side is boxed, because that is where TLS is negotiated.
async fn proxy_connection<C>(
    client_stream: C,
    startup_buf: BytesMut,
    client_addr: String,
    upstream_host: String,
    upstream_port: u16,
    upstream_ssl: UpstreamSsl,
    hex_dump: bool,
    table_mode: bool,
    table_dynamic_width: bool,
) -> Result<()>
where
    C: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    info!(
        "[{}] Connecting to upstream {}:{} (SSL: {})",
        client_addr,
        upstream_host,
        upstream_port,
        upstream_ssl.describe()
    );
    let upstream_socket =
        upstream::connect(&upstream_host, upstream_port, &upstream_ssl, &client_addr).await?;

    info!("[{}] Connected to upstream", client_addr);

    run_proxy(
        client_stream,
        upstream_socket,
        startup_buf,
        client_addr,
        hex_dump,
        table_mode,
        table_dynamic_width,
    )
    .await
}

async fn run_proxy<C>(
    client_stream: C,
    mut upstream_socket: BoxedUpstream,
    startup_buf: BytesMut,
    client_addr: String,
    hex_dump: bool,
    table_mode: bool,
    table_dynamic_width: bool,
) -> Result<()>
where
    C: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    // Forward the startup message to upstream
    upstream_socket.write_all(&startup_buf).await?;
    info!(
        "[{}] → Startup message (length: {})",
        client_addr,
        startup_buf.len()
    );

    // Proxy messages bidirectionally
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_socket);
    let timings = Arc::new(ConnectionTiming::new());
    let client_state = Arc::new(ClientState::new(table_mode, table_dynamic_width));

    let client_addr_clone = client_addr.clone();
    let timings_clone = timings.clone();
    let client_state_clone = client_state.clone();
    let client_to_upstream = tokio::spawn(async move {
        // A message that has not fully arrived stays in `buf` for the next read,
        // so one split over several reads is still decoded. Leaving it there is
        // safe for forwarding: everything already in `buf` has been written out.
        let mut buf = BytesMut::with_capacity(8192);
        loop {
            let handled = buf.len();
            match client_read.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] Client closed connection (session {})",
                        client_addr_clone,
                        format_duration(timings_clone.session_elapsed())
                    );
                    log_undecoded(&buf, &client_addr_clone);
                    break;
                }
                Ok(_) => {
                    // Forward before decoding, so logging cannot delay the proxy.
                    if let Err(e) = upstream_write.write_all(&buf[handled..]).await {
                        error!("[{}] Failed to write to upstream: {}", client_addr_clone, e);
                        break;
                    }

                    // Parse and log
                    parse_message(
                        &mut buf,
                        MessageDirection::ClientToServer,
                        &client_addr_clone,
                        Some(&*timings_clone),
                        &*client_state_clone,
                        hex_dump,
                    );
                }
                Err(e) => {
                    error!("[{}] Failed to read from client: {}", client_addr_clone, e);
                    break;
                }
            }
        }
    });

    let client_addr_clone = client_addr.clone();
    let timings_clone = timings.clone();
    let client_state_clone = client_state.clone();
    let upstream_to_client = tokio::spawn(async move {
        // As above: an incomplete message stays buffered for the next read.
        let mut buf = BytesMut::with_capacity(8192);
        loop {
            let handled = buf.len();
            match upstream_read.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] Upstream closed connection (session {})",
                        client_addr_clone,
                        format_duration(timings_clone.session_elapsed())
                    );
                    log_undecoded(&buf, &client_addr_clone);
                    break;
                }
                Ok(_) => {
                    // Forward before decoding, so logging cannot delay the proxy.
                    if let Err(e) = client_write.write_all(&buf[handled..]).await {
                        error!("[{}] Failed to write to client: {}", client_addr_clone, e);
                        break;
                    }

                    // Parse and log
                    parse_message(
                        &mut buf,
                        MessageDirection::ServerToClient,
                        &client_addr_clone,
                        Some(&*timings_clone),
                        &*client_state_clone,
                        hex_dump,
                    );
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to read from upstream: {}",
                        client_addr_clone, e
                    );
                    break;
                }
            }
        }
    });

    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

    info!(
        "[{}] Connection closed (session {})",
        client_addr,
        format_duration(timings.session_elapsed())
    );
    Ok(())
}
