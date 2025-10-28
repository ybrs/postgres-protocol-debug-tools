use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use clap::{ArgAction, Parser};
use fallible_iterator::FallibleIterator;
use postgres_protocol::message::backend::{
    self, DataRowBody, Message, RowDescriptionBody,
};
use postgres_protocol::message::frontend::{self, BindError};
use postgres_protocol::IsNull;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about = "Inspect raw PostgreSQL protocol responses")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 5432)]
    port: u16,
    #[arg(long)]
    user: String,
    #[arg(long)]
    database: String,
    #[arg(long)]
    query: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    binary_result: bool,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let mut connection = Connection::connect(&args)?;
    connection.startup(&args)?;
    let report = connection.run_extended_query(&args)?;
    report.print();
    connection.terminate()?;
    Ok(())
}

struct Connection {
    stream: TcpStream,
    read_buffer: BytesMut,
}

impl Connection {
    fn connect(args: &Args) -> Result<Self> {
        let addr = format!("{}:{}", args.host, args.port);
        let stream = TcpStream::connect(addr).context("failed to connect to server")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(args.timeout_seconds)))
            .context("unable to set read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(args.timeout_seconds)))
            .context("unable to set write timeout")?;
        stream
            .set_nodelay(true)
            .context("unable to configure TCP_NODELAY")?;
        Ok(Self {
            stream,
            read_buffer: BytesMut::with_capacity(4096),
        })
    }

    fn startup(&mut self, args: &Args) -> Result<()> {
        let parameters = vec![
            ("user".to_string(), args.user.clone()),
            ("database".to_string(), args.database.clone()),
            ("client_encoding".to_string(), "UTF8".to_string()),
            ("application_name".to_string(), "postgres-protocol-inspector".to_string()),
        ];
        let mut buf = BytesMut::new();
        frontend::startup_message(
            parameters
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
            &mut buf,
        )
        .context("failed to encode startup message")?;
        self.stream
            .write_all(&buf)
            .context("failed to send startup message")?;
        self.consume_auth_responses(args)
    }

    fn consume_auth_responses(&mut self, args: &Args) -> Result<()> {
        loop {
            match self.read_message()? {
                Message::AuthenticationOk => continue,
                Message::AuthenticationCleartextPassword => {
                    let password = args
                        .password
                        .as_ref()
                        .context("server requested cleartext password but none provided")?;
                    self.send_password(password)?;
                }
                Message::AuthenticationMd5Password(body) => {
                    let password = args.password.as_ref().context(
                        "server requested md5 password authentication but none provided",
                    )?;
                    let response = md5_password_response(&args.user, password, body.salt());
                    self.send_password(&response)?;
                }
                Message::AuthenticationSasl(body) => {
                    let mut iter = body.mechanisms();
                    let mut mechanisms = Vec::new();
                    while let Some(name) = iter
                        .next()
                        .context("failed to read SASL mechanism")?
                    {
                        mechanisms.push(name.to_string());
                    }
                    bail!("SASL authentication is not supported: {:?}", mechanisms);
                }
                Message::AuthenticationSaslContinue(_) => {
                    bail!("SASL continuation not supported by inspector");
                }
                Message::AuthenticationSaslFinal(_) => {
                    bail!("SASL final message not supported by inspector");
                }
                Message::ParameterStatus(status) => {
                    let name = status.name().unwrap_or("<invalid utf8>");
                    let value = status.value().unwrap_or("<invalid utf8>");
                    println!("parameter: {} = {}", name, value);
                }
                Message::BackendKeyData(data) => {
                    println!(
                        "backend key data: pid={} secret={}",
                        data.process_id(),
                        data.secret_key()
                    );
                }
                Message::ReadyForQuery(state) => {
                    println!("ready for query (transaction state {})", state.status());
                    break;
                }
                Message::ErrorResponse(err) => bail!(format_backend_error(err)?),
                other => {
                    println!("startup message ignored: {:?}", message_tag(&other));
                }
            }
        }
        Ok(())
    }

    fn send_password(&mut self, password: &str) -> Result<()> {
        let mut buf = BytesMut::new();
        frontend::password_message(password.as_bytes(), &mut buf)
            .context("failed to encode password message")?;
        self.stream
            .write_all(&buf)
            .context("failed to send password message")
    }

    fn run_extended_query(&mut self, args: &Args) -> Result<QueryReport> {
        let mut buf = BytesMut::new();
        frontend::parse(
            "stmt1",
            &args.query,
            std::iter::empty::<postgres_protocol::Oid>(),
            &mut buf,
        )
        .context("failed to encode Parse message")?;
        frontend::bind(
            "portal1",
            "stmt1",
            std::iter::empty::<i16>(),
            std::iter::empty::<&[u8]>(),
            |_value: &[u8], _buf| -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
                unreachable!("no parameters expected")
            },
            if args.binary_result { vec![1] } else { vec![0] },
            &mut buf,
        )
        .map_err(|error| match error {
            BindError::Conversion(e) => anyhow!("failed to encode Bind message: {e}"),
            BindError::Serialization(e) => anyhow!("failed to encode Bind message: {e}"),
        })?;
        frontend::describe(b'P', "portal1", &mut buf).context("failed to encode Describe")?;
        frontend::execute("portal1", 0, &mut buf).context("failed to encode Execute")?;
        frontend::sync(&mut buf);
        self.stream
            .write_all(&buf)
            .context("failed to send extended query messages")?;

        let mut report = QueryReport::default();
        loop {
            match self.read_message()? {
                Message::ParseComplete => {
                    println!("parse response: ParseComplete");
                    report.parse_complete = true;
                }
                Message::BindComplete => {
                    println!("bind response: BindComplete");
                    report.bind_complete = true;
                }
                Message::RowDescription(desc) => {
                    let fields = parse_fields(&desc)?;
                    println!("row description arrived:");
                    debug_print_fields(&fields);
                    report.fields = fields;
                }
                Message::DataRow(data_row) => {
                    let parsed_row = parse_data_row(&report.fields, &data_row)?;
                    println!("data row received:");
                    debug_print_row(&report.fields, &parsed_row);
                    report.rows.push(parsed_row);
                }
                Message::CommandComplete(body) => {
                    let tag = body.tag().unwrap_or("<invalid utf8>").to_string();
                    report.command_tag = Some(tag);
                }
                Message::ReadyForQuery(_) => break,
                Message::EmptyQueryResponse => println!("empty query response"),
                Message::ParameterDescription(pd) => {
                    let mut iter = pd.parameters();
                    let mut types = Vec::new();
                    while let Some(oid) = iter
                        .next()
                        .context("failed to read parameter description")?
                    {
                        types.push(oid);
                    }
                    println!("parameter types: {:?}", types);
                }
                Message::NoData => println!("no data response"),
                Message::ErrorResponse(err) => bail!(format_backend_error(err)?),
                Message::NoticeResponse(notice) => {
                    println!("notice: {}", format_error_fields(notice.fields())?);
                }
                Message::NotificationResponse(notification) => {
                    let channel = notification.channel().unwrap_or("<invalid utf8>");
                    let payload = notification.message().unwrap_or("<invalid utf8>");
                    println!("notification: channel={} payload={}", channel, payload);
                }
                other => {
                    println!("unexpected message: {:?}", message_tag(&other));
                }
            }
        }

        Ok(report)
    }

    fn terminate(mut self) -> Result<()> {
        let mut buf = BytesMut::new();
        frontend::terminate(&mut buf);
        self.stream
            .write_all(&buf)
            .context("failed to send Terminate message")
    }

    fn read_message(&mut self) -> Result<Message> {
        loop {
            if let Some(message) = backend::Message::parse(&mut self.read_buffer)
                .context("failed to parse backend message")?
            {
                return Ok(message);
            }

            let mut temp = [0u8; 4096];
            let read = self
                .stream
                .read(&mut temp)
                .context("failed to read from socket")?;
            if read == 0 {
                bail!("server closed the connection unexpectedly");
            }
            self.read_buffer.extend_from_slice(&temp[..read]);
        }
    }
}

#[derive(Default)]
struct QueryReport {
    parse_complete: bool,
    bind_complete: bool,
    fields: Vec<RowField>,
    rows: Vec<Vec<ColumnValue>>,
    command_tag: Option<String>,
}

impl QueryReport {
    fn print(&self) {
        println!("parse complete: {}", self.parse_complete);
        println!("bind complete: {}", self.bind_complete);
        if self.fields.is_empty() {
            println!("no row description returned");
        } else {
            println!("row description ({} column(s)):", self.fields.len());
            for (idx, field) in self.fields.iter().enumerate() {
                println!(
                    "  {}: name='{}' oid={} format={}",
                    idx,
                    field.name,
                    field.type_oid,
                    field.format_label()
                );
            }
        }
        for (row_idx, row) in self.rows.iter().enumerate() {
            println!("row {row_idx}:");
            for (col_idx, value) in row.iter().enumerate() {
                let field = self.fields.get(col_idx);
                let column_name = field.map(|f| f.name.as_str()).unwrap_or("?col");
                let format_label = field.map(|f| f.format_label()).unwrap_or("unknown");
                println!(
                    "  {} ({} / {}): {}",
                    col_idx,
                    column_name,
                    format_label,
                    wrap_column_value(value)
                );
            }
        }
        if let Some(tag) = &self.command_tag {
            println!("command tag: {tag}");
        }
    }
}

#[derive(Clone)]
struct RowField {
    name: String,
    type_oid: u32,
    format: i16,
}

impl RowField {
    fn format_label(&self) -> &str {
        match self.format {
            0 => "text",
            1 => "binary",
            _ => "unknown",
        }
    }
}

fn debug_print_fields(fields: &[RowField]) {
    if fields.is_empty() {
        println!("  (no columns)");
        return;
    }
    for (idx, field) in fields.iter().enumerate() {
        println!(
            "  col {idx}: name='{}' oid={} format={}",
            field.name, field.type_oid, field.format_label()
        );
    }
}

#[derive(Clone)]
enum ColumnValue {
    Null,
    Bytes(Vec<u8>),
}

fn debug_print_row(fields: &[RowField], values: &[ColumnValue]) {
    for (idx, value) in values.iter().enumerate() {
        let field = fields.get(idx);
        let name = field.map(|f| f.name.as_str()).unwrap_or("<unnamed>");
        let format = field.map(|f| f.format_label()).unwrap_or("unknown");
        println!(
            "    col {idx} ({name} / {format}): {}",
            wrap_column_value(value)
        );
    }
}

fn wrap_column_value(value: &ColumnValue) -> String {
    match value {
        ColumnValue::Null => "<NULL>".to_string(),
        ColumnValue::Bytes(bytes) => format_value(bytes),
    }
}

fn format_value(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) if text.is_ascii() => format!("text:'{}'", text),
        _ => format!("hex:{}", hex_string(bytes)),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push_str("0x");
    for byte in bytes {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn parse_fields(description: &RowDescriptionBody) -> Result<Vec<RowField>> {
    let mut fields_iter = description.fields();
    let mut fields = Vec::new();
    while let Some(field) = fields_iter
        .next()
        .context("failed to read row description field")?
    {
        fields.push(RowField {
            name: field.name().to_string(),
            type_oid: field.type_oid(),
            format: field.format(),
        });
    }
    Ok(fields)
}

fn parse_data_row(fields: &[RowField], row: &DataRowBody) -> Result<Vec<ColumnValue>> {
    let mut iter = row.ranges();
    let mut values = Vec::new();
    let buffer = row.buffer();
    while let Some(range) = iter.next().context("failed to parse data row value")? {
        match range {
            Some(range) => {
                values.push(ColumnValue::Bytes(buffer[range].to_vec()));
            }
            None => values.push(ColumnValue::Null),
        }
    }
    if fields.len() != values.len() {
        println!(
            "warning: row has {} values but description has {} columns",
            values.len(),
            fields.len()
        );
    }
    Ok(values)
}

fn md5_password_response(user: &str, password: &str, salt: [u8; 4]) -> String {
    let mut inner = Vec::with_capacity(password.len() + user.len());
    inner.extend_from_slice(password.as_bytes());
    inner.extend_from_slice(user.as_bytes());
    let first_hash = format!("{:x}", md5::compute(inner));

    let mut outer = Vec::with_capacity(first_hash.len() + salt.len());
    outer.extend_from_slice(first_hash.as_bytes());
    outer.extend_from_slice(&salt);
    format!("md5{:x}", md5::compute(outer))
}

fn format_backend_error(body: backend::ErrorResponseBody) -> Result<String> {
    Ok(format_error_fields(body.fields())?)
}

fn format_error_fields(
    fields: backend::ErrorFields<'_>,
) -> Result<String> {
    let mut iter = fields;
    let mut parts = Vec::new();
    while let Some(field) = iter.next().context("failed to read error field")? {
        let value = std::str::from_utf8(field.value_bytes())
            .unwrap_or("<non-utf8>");
        parts.push(format!("{}={}", field.type_() as char, value));
    }
    Ok(parts.join(" "))
}

fn message_tag(message: &Message) -> &'static str {
    match message {
        Message::AuthenticationCleartextPassword => "AuthenticationCleartextPassword",
        Message::AuthenticationMd5Password(_) => "AuthenticationMd5Password",
        Message::AuthenticationOk => "AuthenticationOk",
        Message::BackendKeyData(_) => "BackendKeyData",
        Message::BindComplete => "BindComplete",
        Message::CommandComplete(_) => "CommandComplete",
        Message::DataRow(_) => "DataRow",
        Message::EmptyQueryResponse => "EmptyQueryResponse",
        Message::ErrorResponse(_) => "ErrorResponse",
        Message::NoData => "NoData",
        Message::NoticeResponse(_) => "NoticeResponse",
        Message::NotificationResponse(_) => "NotificationResponse",
        Message::ParameterDescription(_) => "ParameterDescription",
        Message::ParameterStatus(_) => "ParameterStatus",
        Message::ParseComplete => "ParseComplete",
        Message::ReadyForQuery(_) => "ReadyForQuery",
        Message::RowDescription(_) => "RowDescription",
        other => {
            let _ = other;
            "Other"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_hex_string() {
        let input = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_string(&input), "0xdeadbeef");
    }

    #[test]
    fn test_format_value_with_ascii() {
        assert_eq!(format_value(b"hello"), "text:'hello'");
    }

    #[test]
    fn test_format_value_with_binary() {
        let bytes = decode("000102ff").unwrap();
        assert_eq!(format_value(&bytes), "hex:0x000102ff");
    }

    #[test]
    fn test_md5_password_response() {
        // Example derived from PostgreSQL documentation
        let response = md5_password_response("user", "password", [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(response, "md5d6f407104ca5ba8553d598fed7df90e0");
    }
}
