use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::info;

use crate::table_formatter::{FieldInfo, TableState};

#[derive(Debug)]
pub enum MessageDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Default)]
struct TimingState {
    simple_query: Option<Instant>,
    execute: Option<Instant>,
    parse: Option<Instant>,
    bind: Option<Instant>,
}

pub struct ConnectionTiming {
    start: Instant,
    state: Mutex<TimingState>,
}

impl ConnectionTiming {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            state: Mutex::new(TimingState::default()),
        }
    }

    pub fn mark_simple_query(&self) {
        self.state.lock().unwrap().simple_query = Some(Instant::now());
    }

    pub fn mark_execute(&self) {
        self.state.lock().unwrap().execute = Some(Instant::now());
    }

    pub fn mark_parse(&self) {
        self.state.lock().unwrap().parse = Some(Instant::now());
    }

    pub fn mark_bind(&self) {
        self.state.lock().unwrap().bind = Some(Instant::now());
    }

    pub fn finish_simple_query(&self) -> Option<Duration> {
        self.state
            .lock()
            .unwrap()
            .simple_query
            .take()
            .map(|start| start.elapsed())
    }

    pub fn finish_execute(&self) -> Option<Duration> {
        self.state
            .lock()
            .unwrap()
            .execute
            .take()
            .map(|start| start.elapsed())
    }

    pub fn finish_parse(&self) -> Option<Duration> {
        self.state
            .lock()
            .unwrap()
            .parse
            .take()
            .map(|start| start.elapsed())
    }

    pub fn finish_bind(&self) -> Option<Duration> {
        self.state
            .lock()
            .unwrap()
            .bind
            .take()
            .map(|start| start.elapsed())
    }

    pub fn session_elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

pub fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

/// Per-client state for managing table formatting and row descriptions
pub struct ClientState {
    table_state: TableState,
}

impl ClientState {
    pub fn new(table_mode: bool) -> Self {
        Self {
            table_state: TableState::new(table_mode),
        }
    }
}

pub fn parse_message(
    data: &[u8],
    direction: MessageDirection,
    client_addr: &str,
    timings: Option<&ConnectionTiming>,
    client_state: &ClientState,
    hex_dump: bool,
) {
    let mut buf = data;
    let arrow = match direction {
        MessageDirection::ClientToServer => "→",
        MessageDirection::ServerToClient => "←",
    };

    while buf.len() >= 5 {
        let msg_type = buf[0] as char;
        let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

        if buf.len() < length + 1 {
            // Incomplete message
            break;
        }

        // Full message including type byte and length
        let full_message = &buf[..length + 1];
        let msg_data = &buf[5..length + 1];

        match direction {
            MessageDirection::ClientToServer => {
                parse_client_message(msg_type, msg_data, client_addr, arrow, timings, client_state);
            }
            MessageDirection::ServerToClient => {
                parse_server_message(msg_type, msg_data, client_addr, arrow, timings, client_state);
            }
        }

        // Log hex dump
        if hex_dump {
            log_hex_dump(full_message, client_addr);
        }

        buf = &buf[length + 1..];
    }

    // If there's remaining data that doesn't form a complete message
    if !buf.is_empty() && buf.len() < 5 {
        info!(
            "[{}] {} Partial message ({} bytes)",
            client_addr,
            arrow,
            buf.len()
        );
    }
}

fn log_hex_dump(data: &[u8], client_addr: &str) {
    const BYTES_PER_LINE: usize = 16;

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let offset = i * BYTES_PER_LINE;
        let hex_string: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii_string: String = chunk
            .iter()
            .map(|&b| {
                if b >= 0x20 && b <= 0x7e {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        info!(
            "[{}]   {:04x}: {:<48}  {}",
            client_addr, offset, hex_string, ascii_string
        );
    }
}

fn parse_client_message(
    msg_type: char,
    data: &[u8],
    client_addr: &str,
    arrow: &str,
    timings: Option<&ConnectionTiming>,
    _client_state: &ClientState,
) {
    match msg_type {
        'Q' => {
            // Simple query
            if let Some(t) = timings {
                t.mark_simple_query();
            }
            if let Ok(query) = std::str::from_utf8(&data[..data.len().saturating_sub(1)]) {
                info!("[{}] {} Query: {}", client_addr, arrow, query);
            } else {
                info!(
                    "[{}] {} Query (invalid UTF-8, {} bytes)",
                    client_addr,
                    arrow,
                    data.len()
                );
            }
        }
        'P' => {
            // Parse (prepared statement)
            if let Some(t) = timings {
                t.mark_parse();
            }
            info!(
                "[{}] {} Parse (prepared statement, {} bytes)",
                client_addr,
                arrow,
                data.len()
            );
            if let Some(details) = parse_parse_message(data) {
                info!("[{}]    {}", client_addr, details);
            }
        }
        'B' => {
            // Bind
            if let Some(t) = timings {
                t.mark_bind();
            }
            info!("[{}] {} Bind ({} bytes)", client_addr, arrow, data.len());
            if let Some(bind_info) = parse_bind_message(data) {
                info!("[{}]    {}", client_addr, bind_info);
            }
        }
        'E' => {
            // Execute
            if let Some(t) = timings {
                t.mark_execute();
            }
            info!("[{}] {} Execute ({} bytes)", client_addr, arrow, data.len());
        }
        'D' => {
            // Describe
            if data.is_empty() {
                info!("[{}] {} Describe (unknown)", client_addr, arrow);
                return;
            }

            let describe_target = data[0] as char;
            let name = if data.len() > 1 {
                let rest = &data[1..];
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                let raw = &rest[..end];
                String::from_utf8_lossy(raw).to_string()
            } else {
                String::new()
            };
            let formatted_name = if name.is_empty() {
                "(unnamed)".to_string()
            } else {
                name
            };

            let describe_type = match describe_target {
                'S' => "statement",
                'P' => "portal",
                _ => "unknown",
            };

            match describe_target {
                'S' => info!(
                    "[{}] {} Describe (statement '{}', {} bytes)",
                    client_addr,
                    arrow,
                    formatted_name,
                    data.len()
                ),
                'P' => info!(
                    "[{}] {} Describe (portal '{}', {} bytes)",
                    client_addr,
                    arrow,
                    formatted_name,
                    data.len()
                ),
                _ => info!(
                    "[{}] {} Describe ({}, {} bytes)",
                    client_addr,
                    arrow,
                    describe_type,
                    data.len()
                ),
            };
        }
        'S' => {
            // Sync
            info!("[{}] {} Sync", client_addr, arrow);
        }
        'X' => {
            // Terminate
            info!("[{}] {} Terminate", client_addr, arrow);
        }
        'p' => {
            // Password message
            info!(
                "[{}] {} PasswordMessage ({} bytes)",
                client_addr,
                arrow,
                data.len()
            );
        }
        'C' => {
            // Close
            info!("[{}] {} Close ({} bytes)", client_addr, arrow, data.len());
        }
        'H' => {
            // Flush
            info!("[{}] {} Flush", client_addr, arrow);
        }
        'd' => {
            // CopyData
            info!(
                "[{}] {} CopyData ({} bytes)",
                client_addr,
                arrow,
                data.len()
            );
        }
        'c' => {
            // CopyDone
            info!("[{}] {} CopyDone", client_addr, arrow);
        }
        'f' => {
            // CopyFail
            if let Ok(msg) = std::str::from_utf8(&data[..data.len().saturating_sub(1)]) {
                info!("[{}] {} CopyFail: {}", client_addr, arrow, msg);
            } else {
                info!("[{}] {} CopyFail", client_addr, arrow);
            }
        }
        _ => {
            info!(
                "[{}] {} Unknown message type '{}' ({} bytes)",
                client_addr,
                arrow,
                msg_type,
                data.len()
            );
        }
    }
}

fn parse_server_message(
    msg_type: char,
    data: &[u8],
    client_addr: &str,
    arrow: &str,
    timings: Option<&ConnectionTiming>,
    client_state: &ClientState,
) {
    match msg_type {
        'R' => {
            // Authentication
            if data.len() >= 4 {
                let auth_type = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let auth_name = match auth_type {
                    0 => "AuthenticationOk",
                    2 => "AuthenticationKerberosV5",
                    3 => "AuthenticationCleartextPassword",
                    5 => "AuthenticationMD5Password",
                    6 => "AuthenticationSCMCredential",
                    7 => "AuthenticationGSS",
                    8 => "AuthenticationGSSContinue",
                    9 => "AuthenticationSSPI",
                    10 => "AuthenticationSASL",
                    11 => "AuthenticationSASLContinue",
                    12 => "AuthenticationSASLFinal",
                    _ => "Unknown",
                };
                info!("[{}] {} Authentication: {}", client_addr, arrow, auth_name);
            } else {
                info!("[{}] {} Authentication", client_addr, arrow);
            }
        }
        'K' => {
            // BackendKeyData
            info!("[{}] {} BackendKeyData", client_addr, arrow);
        }
        'Z' => {
            // ReadyForQuery
            let status = if !data.is_empty() {
                match data[0] as char {
                    'I' => "idle",
                    'T' => "in transaction",
                    'E' => "error in transaction",
                    _ => "unknown",
                }
            } else {
                "unknown"
            };
            info!("[{}] {} ReadyForQuery ({})", client_addr, arrow, status);
        }
        'S' => {
            // ParameterStatus
            if let Some((name, value)) = parse_cstring_pair(data) {
                info!(
                    "[{}] {} ParameterStatus: {} = {}",
                    client_addr, arrow, name, value
                );
            } else {
                info!("[{}] {} ParameterStatus", client_addr, arrow);
            }
        }
        'T' => {
            // RowDescription
            if data.len() >= 2 {
                let field_count = u16::from_be_bytes([data[0], data[1]]);
                info!(
                    "[{}] {} RowDescription ({} fields)",
                    client_addr, arrow, field_count
                );
                if let Some(fields) = parse_row_description(data) {
                    for (i, field) in fields.iter().enumerate() {
                        info!("[{}]    Field {}: {}", client_addr, i + 1, field.description);
                    }

                    // Set up table formatter if in table mode
                    if client_state.table_state.is_table_mode() {
                        let field_infos: Vec<FieldInfo> = fields
                            .iter()
                            .map(|f| f.field_info.clone())
                            .collect();
                        client_state.table_state.set_row_description(field_infos);
                    }
                }
            } else {
                info!("[{}] {} RowDescription", client_addr, arrow);
            }
        }
        'D' => {
            // DataRow
            if data.len() >= 2 {
                let field_count = u16::from_be_bytes([data[0], data[1]]);

                if let Some(values) = parse_data_row(data) {
                    // If in table mode, print as table row
                    if client_state.table_state.is_table_mode() {
                        client_state.table_state.print_data_row(&values, client_addr);
                    } else {
                        // Original logging format
                        info!(
                            "[{}] {} DataRow ({} fields, {} bytes)",
                            client_addr,
                            arrow,
                            field_count,
                            data.len()
                        );
                        for (i, value) in values.iter().enumerate() {
                            info!("[{}]    Value {}: {}", client_addr, i + 1, value);
                        }
                    }
                }
            } else {
                info!("[{}] {} DataRow ({} bytes)", client_addr, arrow, data.len());
            }
        }
        'C' => {
            // CommandComplete
            // Finish table formatting if active
            if client_state.table_state.is_table_mode() {
                client_state.table_state.finish_result_set(client_addr);
            }

            let tag = std::str::from_utf8(&data[..data.len().saturating_sub(1)]).ok();
            if let Some(t) = timings {
                if let Some(duration) = t.finish_simple_query() {
                    if let Some(tag) = tag {
                        info!(
                            "[{}] {} CommandComplete: {} (query took {})",
                            client_addr,
                            arrow,
                            tag,
                            format_duration(duration)
                        );
                    } else {
                        info!(
                            "[{}] {} CommandComplete (query took {})",
                            client_addr,
                            arrow,
                            format_duration(duration)
                        );
                    }
                    return;
                } else if let Some(duration) = t.finish_execute() {
                    if let Some(tag) = tag {
                        info!(
                            "[{}] {} CommandComplete: {} (execute took {})",
                            client_addr,
                            arrow,
                            tag,
                            format_duration(duration)
                        );
                    } else {
                        info!(
                            "[{}] {} CommandComplete (execute took {})",
                            client_addr,
                            arrow,
                            format_duration(duration)
                        );
                    }
                    return;
                }
            }

            if let Some(tag) = tag {
                info!("[{}] {} CommandComplete: {}", client_addr, arrow, tag);
            } else {
                info!("[{}] {} CommandComplete", client_addr, arrow);
            }
        }
        'E' => {
            // ErrorResponse
            info!("[{}] {} ErrorResponse", client_addr, arrow);
            if let Some(error_msg) = parse_error_response(data) {
                info!("[{}]    {}", client_addr, error_msg);
            }
        }
        'N' => {
            // NoticeResponse
            info!("[{}] {} NoticeResponse", client_addr, arrow);
            if let Some(notice_msg) = parse_error_response(data) {
                info!("[{}]    {}", client_addr, notice_msg);
            }
        }
        '1' => {
            // ParseComplete
            if let Some(t) = timings {
                if let Some(duration) = t.finish_parse() {
                    info!(
                        "[{}] {} ParseComplete (took {})",
                        client_addr,
                        arrow,
                        format_duration(duration)
                    );
                    return;
                }
            }
            info!("[{}] {} ParseComplete", client_addr, arrow);
        }
        '2' => {
            // BindComplete
            if let Some(t) = timings {
                if let Some(duration) = t.finish_bind() {
                    info!(
                        "[{}] {} BindComplete (took {})",
                        client_addr,
                        arrow,
                        format_duration(duration)
                    );
                    return;
                }
            }
            info!("[{}] {} BindComplete", client_addr, arrow);
        }
        '3' => {
            // CloseComplete
            info!("[{}] {} CloseComplete", client_addr, arrow);
        }
        'n' => {
            // NoData
            info!("[{}] {} NoData", client_addr, arrow);
        }
        's' => {
            // PortalSuspended
            info!("[{}] {} PortalSuspended", client_addr, arrow);
        }
        't' => {
            // ParameterDescription
            if data.len() >= 2 {
                let param_count = u16::from_be_bytes([data[0], data[1]]);
                info!(
                    "[{}] {} ParameterDescription ({} parameters)",
                    client_addr, arrow, param_count
                );
                if let Some(params) = parse_parameter_description(data) {
                    for (i, param) in params.iter().enumerate() {
                        info!("[{}]    Param {}: {}", client_addr, i + 1, param);
                    }
                }
            } else {
                info!("[{}] {} ParameterDescription", client_addr, arrow);
            }
        }
        'I' => {
            // EmptyQueryResponse
            info!("[{}] {} EmptyQueryResponse", client_addr, arrow);
        }
        'd' => {
            // CopyData
            info!(
                "[{}] {} CopyData ({} bytes)",
                client_addr,
                arrow,
                data.len()
            );
        }
        'c' => {
            // CopyDone
            info!("[{}] {} CopyDone", client_addr, arrow);
        }
        'G' => {
            // CopyInResponse
            info!("[{}] {} CopyInResponse", client_addr, arrow);
        }
        'H' => {
            // CopyOutResponse
            info!("[{}] {} CopyOutResponse", client_addr, arrow);
        }
        'W' => {
            // CopyBothResponse
            info!("[{}] {} CopyBothResponse", client_addr, arrow);
        }
        _ => {
            info!(
                "[{}] {} Unknown message type '{}' ({} bytes)",
                client_addr,
                arrow,
                msg_type,
                data.len()
            );
        }
    }
}

fn parse_cstring_pair(data: &[u8]) -> Option<(String, String)> {
    let mut parts = data.split(|&b| b == 0);
    let name = parts.next()?.to_vec();
    let value = parts.next()?.to_vec();

    Some((
        String::from_utf8_lossy(&name).to_string(),
        String::from_utf8_lossy(&value).to_string(),
    ))
}

fn parse_error_response(data: &[u8]) -> Option<String> {
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let field_type = data[i] as char;
        if field_type == '\0' {
            break;
        }

        i += 1;
        let mut field_value = Vec::new();
        while i < data.len() && data[i] != 0 {
            field_value.push(data[i]);
            i += 1;
        }
        i += 1; // Skip null terminator

        let value = String::from_utf8_lossy(&field_value);

        let field_name = match field_type {
            'S' => "Severity",
            'V' => "Severity",
            'C' => "Code",
            'M' => "Message",
            'D' => "Detail",
            'H' => "Hint",
            'P' => "Position",
            'p' => "Internal position",
            'q' => "Internal query",
            'W' => "Where",
            's' => "Schema",
            't' => "Table",
            'c' => "Column",
            'd' => "Data type",
            'n' => "Constraint",
            'F' => "File",
            'L' => "Line",
            'R' => "Routine",
            _ => "Unknown",
        };

        if !result.is_empty() {
            result.push_str(", ");
        }
        result.push_str(&format!("{}: {}", field_name, value));
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn parse_parse_message(data: &[u8]) -> Option<String> {
    let mut i = 0;

    // Statement name
    let mut stmt_name = Vec::new();
    while i < data.len() && data[i] != 0 {
        stmt_name.push(data[i]);
        i += 1;
    }
    i += 1; // Skip null terminator

    // Query string
    let mut query = Vec::new();
    while i < data.len() && data[i] != 0 {
        query.push(data[i]);
        i += 1;
    }

    let stmt_name_str = String::from_utf8_lossy(&stmt_name);
    let query_str = String::from_utf8_lossy(&query);

    if stmt_name_str.is_empty() && query_str.is_empty() {
        None
    } else {
        Some(format!(
            "Statement: '{}', Query: '{}'",
            if stmt_name_str.is_empty() {
                "(unnamed)"
            } else {
                &stmt_name_str
            },
            query_str
        ))
    }
}

struct RowDescriptionField {
    field_info: FieldInfo,
    description: String,
}

fn parse_row_description(data: &[u8]) -> Option<Vec<RowDescriptionField>> {
    if data.len() < 2 {
        return None;
    }

    let field_count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut fields = Vec::new();
    let mut i = 2;

    for _ in 0..field_count {
        // Field name (null-terminated string)
        let mut field_name = Vec::new();
        while i < data.len() && data[i] != 0 {
            field_name.push(data[i]);
            i += 1;
        }
        i += 1; // Skip null terminator

        if i + 18 > data.len() {
            break;
        }

        // Table OID (4 bytes)
        let _table_oid = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        // Column attribute number (2 bytes)
        let _col_attr = u16::from_be_bytes([data[i], data[i + 1]]);
        i += 2;

        // Type OID (4 bytes)
        let type_oid = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        // Type size (2 bytes, signed)
        let type_size = i16::from_be_bytes([data[i], data[i + 1]]);
        i += 2;

        // Type modifier (4 bytes, signed)
        let type_mod = i32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        // Format code (2 bytes)
        let format_code = u16::from_be_bytes([data[i], data[i + 1]]);
        i += 2;

        let format_str = match format_code {
            0 => "text",
            1 => "binary",
            _ => "unknown",
        };

        let type_name = get_pg_type_name(type_oid);
        let name_str = String::from_utf8_lossy(&field_name).to_string();

        let description = format!(
            "name='{}', type={} (OID={}), size={}, typemod={}, format={}",
            name_str, type_name, type_oid, type_size, type_mod, format_str
        );

        fields.push(RowDescriptionField {
            field_info: FieldInfo {
                name: name_str,
                type_name: type_name.to_string(),
            },
            description,
        });
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn parse_data_row(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let field_count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut values = Vec::new();
    let mut i = 2;

    for _ in 0..field_count {
        if i + 4 > data.len() {
            break;
        }

        // Field length (4 bytes, -1 = NULL)
        let length = i32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        if length == -1 {
            values.push("NULL".to_string());
        } else if length >= 0 {
            let length = length as usize;
            if i + length > data.len() {
                break;
            }

            let value_bytes = &data[i..i + length];
            i += length;

            // Try to display as UTF-8 string, otherwise show hex
            match std::str::from_utf8(value_bytes) {
                Ok(s) => {
                    // Truncate long values
                    if s.len() > 100 {
                        values.push(format!("'{}...' ({} bytes)", &s[..100], s.len()));
                    } else {
                        values.push(format!("'{}'", s));
                    }
                }
                Err(_) => {
                    // Binary data, show hex
                    let hex: String = value_bytes
                        .iter()
                        .take(32) // Show first 32 bytes max
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if value_bytes.len() > 32 {
                        values.push(format!(
                            "<binary: {} ...> ({} bytes)",
                            hex,
                            value_bytes.len()
                        ));
                    } else {
                        values.push(format!("<binary: {}>", hex));
                    }
                }
            }
        }
    }

    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn get_pg_type_name(oid: u32) -> &'static str {
    match oid {
        16 => "bool",
        17 => "bytea",
        18 => "char",
        19 => "name",
        20 => "int8",
        21 => "int2",
        23 => "int4",
        25 => "text",
        26 => "oid",
        114 => "json",
        142 => "xml",
        700 => "float4",
        701 => "float8",
        1000 => "bool[]",
        1001 => "bytea[]",
        1002 => "char[]",
        1003 => "name[]",
        1005 => "int2[]",
        1007 => "int4[]",
        1009 => "text[]",
        1014 => "char[]",
        1015 => "varchar[]",
        1016 => "int8[]",
        1021 => "float4[]",
        1022 => "float8[]",
        1042 => "bpchar",
        1043 => "varchar",
        1082 => "date",
        1083 => "time",
        1114 => "timestamp",
        1184 => "timestamptz",
        1186 => "interval",
        1266 => "timetz",
        1560 => "bit",
        1562 => "varbit",
        1700 => "numeric",
        2950 => "uuid",
        3802 => "jsonb",
        _ => "unknown",
    }
}

fn parse_bind_message(data: &[u8]) -> Option<String> {
    let mut i = 0;

    let portal_name = read_cstring(data, &mut i)?;
    let stmt_name = read_cstring(data, &mut i)?;

    if i + 2 > data.len() {
        return None;
    }

    // Parameter format codes
    let param_format_count = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;
    let mut param_formats = Vec::new();
    for _ in 0..param_format_count {
        if i + 2 > data.len() {
            return None;
        }
        param_formats.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    if i + 2 > data.len() {
        return None;
    }

    // Parameter count
    let param_count = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;

    // Skip parameter values
    for _ in 0..param_count {
        if i + 4 > data.len() {
            return None;
        }
        let value_len = i32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        if value_len < 0 {
            continue;
        }

        let value_len = value_len as usize;
        if i + value_len > data.len() {
            return None;
        }
        i += value_len;
    }

    if i + 2 > data.len() {
        return None;
    }

    // Result format codes
    let result_format_count = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;
    let mut result_formats = Vec::new();
    for _ in 0..result_format_count {
        if i + 2 > data.len() {
            return None;
        }
        result_formats.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    let portal_str = format_identifier(&portal_name);
    let stmt_str = format_identifier(&stmt_name);
    let param_formats_desc =
        describe_format_codes("ParamFormats", param_format_count, &param_formats);
    let result_formats_desc =
        describe_format_codes("ResultFormats", result_format_count, &result_formats);

    Some(format!(
        "Portal='{}', Statement='{}', Parameters={}, {}, {}",
        portal_str, stmt_str, param_count, param_formats_desc, result_formats_desc
    ))
}

fn read_cstring(data: &[u8], index: &mut usize) -> Option<Vec<u8>> {
    if *index >= data.len() {
        return None;
    }

    let start = *index;
    while *index < data.len() && data[*index] != 0 {
        *index += 1;
    }

    if *index >= data.len() {
        return None;
    }

    let value = data[start..*index].to_vec();
    *index += 1; // Skip null terminator
    Some(value)
}

fn format_identifier(bytes: &[u8]) -> String {
    let name = String::from_utf8_lossy(bytes).to_string();
    if name.is_empty() {
        "(unnamed)".to_string()
    } else {
        name
    }
}

fn describe_format_codes(label: &str, count: u16, codes: &[u16]) -> String {
    match count {
        0 => format!("{label}=text (all)"),
        1 => {
            let code = codes.get(0).copied().unwrap_or(0);
            format!("{label}={} (all)", format_format(code))
        }
        _ => {
            let formats = codes
                .iter()
                .map(|code| format_format(*code))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{label}=[{}]", formats)
        }
    }
}

fn format_format(code: u16) -> &'static str {
    match code {
        0 => "text",
        1 => "binary",
        _ => "unknown",
    }
}

fn parse_parameter_description(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let param_count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut params = Vec::new();
    let mut i = 2;

    for _ in 0..param_count {
        if i + 4 > data.len() {
            break;
        }

        // Parameter type OID (4 bytes)
        let type_oid = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        let type_name = get_pg_type_name(type_oid);
        params.push(format!("type={} (OID={})", type_name, type_oid));
    }

    if params.is_empty() {
        None
    } else {
        Some(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_query_timing_measures_once() {
        let timing = ConnectionTiming::new();
        timing.mark_simple_query();
        assert!(timing.finish_simple_query().is_some());
        assert!(timing.finish_simple_query().is_none());
    }

    #[test]
    fn format_duration_outputs_seconds() {
        let dur = Duration::from_millis(1500);
        assert_eq!(format_duration(dur), "1.500s");
    }

    #[test]
    fn bind_message_reports_all_binary_result_format() {
        let data = vec![
            0, // portal ""
            b'_', b'p', b'1', 0, // statement "_p1"
            0, 0, // param format count = 0
            0, 0, // param count = 0
            0, 1, // result format count = 1
            0, 1, // binary for all
        ];

        let summary = parse_bind_message(&data).expect("bind parsed");
        assert!(
            summary.contains("ResultFormats=binary (all)"),
            "summary missing binary all: {summary}"
        );
        assert!(
            summary.contains("ParamFormats=text (all)"),
            "summary missing default param format: {summary}"
        );
    }

    #[test]
    fn bind_message_reports_per_column_formats() {
        let data = vec![
            0, // portal ""
            b'_', b'p', b'1', 0, // statement "_p1"
            0, 1, // param format count = 1
            0, 1, // binary params
            0, 0, // param count = 0
            0, 2, // result format count = 2
            0, 0, // column 1 text
            0, 1, // column 2 binary
        ];

        let summary = parse_bind_message(&data).expect("bind parsed");
        assert!(
            summary.contains("ParamFormats=binary (all)"),
            "summary missing binary params: {summary}"
        );
        assert!(
            summary.contains("ResultFormats=[text, binary]"),
            "summary missing per-column formats: {summary}"
        );
    }
}
