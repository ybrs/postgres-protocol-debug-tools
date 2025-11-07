use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::Parser;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

mod protocol;
use protocol::{format_duration, parse_message, ConnectionTiming, MessageDirection};
mod logging;
use logging::{setup_logging, LogFormat};

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
    #[arg(long, value_enum, default_value_t = LogFormat::Full)]
    log_format: LogFormat,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    setup_logging(args.log_file.as_ref(), args.log_format)?;

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
        "Forwarding to {}:{}",
        args.upstream_host, args.upstream_port
    );

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        info!("New connection from {}", client_addr);

        let upstream_host = args.upstream_host.clone();
        let upstream_port = args.upstream_port;
        let ssl_config = ssl_config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                client_socket,
                client_addr.to_string(),
                upstream_host,
                upstream_port,
                ssl_config,
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

async fn handle_connection(
    mut client_socket: TcpStream,
    client_addr: String,
    upstream_host: String,
    upstream_port: u16,
    ssl_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    // Check if client wants SSL
    let mut startup_buf = BytesMut::with_capacity(8);
    client_socket
        .read_buf(&mut startup_buf)
        .await
        .context("Failed to read startup")?;

    if startup_buf.len() < 8 {
        warn!("Client disconnected during startup");
        return Ok(());
    }

    let _length = u32::from_be_bytes([
        startup_buf[0],
        startup_buf[1],
        startup_buf[2],
        startup_buf[3],
    ]);
    let protocol = u32::from_be_bytes([
        startup_buf[4],
        startup_buf[5],
        startup_buf[6],
        startup_buf[7],
    ]);

    // SSL request code is 80877103
    if protocol == 80877103 {
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

            // Now read the actual startup message
            startup_buf.clear();
            tls_stream
                .read_buf(&mut startup_buf)
                .await
                .context("Failed to read startup after SSL")?;

            // Connect to upstream and proxy with TLS stream
            return proxy_with_tls(
                tls_stream,
                startup_buf,
                client_addr,
                upstream_host,
                upstream_port,
            )
            .await;
        } else {
            // Reject SSL
            client_socket.write_all(&[b'N']).await?;
            info!("[{}] SSL rejected (not configured)", client_addr);

            // Now read the actual startup message
            startup_buf.clear();
            client_socket
                .read_buf(&mut startup_buf)
                .await
                .context("Failed to read startup after SSL rejection")?;
        }
    }

    // Non-SSL path
    proxy_with_tcp(
        client_socket,
        startup_buf,
        client_addr,
        upstream_host,
        upstream_port,
    )
    .await
}

async fn proxy_with_tls(
    client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    startup_buf: BytesMut,
    client_addr: String,
    upstream_host: String,
    upstream_port: u16,
) -> Result<()> {
    // Connect to upstream
    info!(
        "[{}] Connecting to upstream {}:{}",
        client_addr, upstream_host, upstream_port
    );
    let upstream_socket = TcpStream::connect(format!("{}:{}", upstream_host, upstream_port))
        .await
        .context("Failed to connect to upstream")?;

    info!("[{}] Connected to upstream", client_addr);

    run_proxy(client_stream, upstream_socket, startup_buf, client_addr).await
}

async fn proxy_with_tcp(
    client_stream: TcpStream,
    startup_buf: BytesMut,
    client_addr: String,
    upstream_host: String,
    upstream_port: u16,
) -> Result<()> {
    // Connect to upstream
    info!(
        "[{}] Connecting to upstream {}:{}",
        client_addr, upstream_host, upstream_port
    );
    let upstream_socket = TcpStream::connect(format!("{}:{}", upstream_host, upstream_port))
        .await
        .context("Failed to connect to upstream")?;

    info!("[{}] Connected to upstream", client_addr);

    run_proxy(client_stream, upstream_socket, startup_buf, client_addr).await
}

async fn run_proxy<C>(
    client_stream: C,
    mut upstream_socket: TcpStream,
    startup_buf: BytesMut,
    client_addr: String,
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
    let (mut upstream_read, mut upstream_write) = upstream_socket.into_split();
    let timings = Arc::new(ConnectionTiming::new());

    let client_addr_clone = client_addr.clone();
    let timings_clone = timings.clone();
    let client_to_upstream = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(8192);
        loop {
            buf.clear();
            match client_read.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] Client closed connection (session {})",
                        client_addr_clone,
                        format_duration(timings_clone.session_elapsed())
                    );
                    break;
                }
                Ok(n) => {
                    // Parse and log
                    parse_message(
                        &buf[..n],
                        MessageDirection::ClientToServer,
                        &client_addr_clone,
                        Some(&*timings_clone),
                    );

                    // Forward to upstream
                    if let Err(e) = upstream_write.write_all(&buf[..n]).await {
                        error!("[{}] Failed to write to upstream: {}", client_addr_clone, e);
                        break;
                    }
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
    let upstream_to_client = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(8192);
        loop {
            buf.clear();
            match upstream_read.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] Upstream closed connection (session {})",
                        client_addr_clone,
                        format_duration(timings_clone.session_elapsed())
                    );
                    break;
                }
                Ok(n) => {
                    // Parse and log
                    parse_message(
                        &buf[..n],
                        MessageDirection::ServerToClient,
                        &client_addr_clone,
                        Some(&*timings_clone),
                    );

                    // Forward to client
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        error!("[{}] Failed to write to client: {}", client_addr_clone, e);
                        break;
                    }
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
