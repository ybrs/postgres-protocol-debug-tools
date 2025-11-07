use anyhow::{Context, Result};
use clap::ValueEnum;
use owo_colors::{AnsiColors, OwoColorize};
use std::fmt::{self, Write as FmtWrite};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FormatEvent, FormatFields};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogFormat {
    #[value(name = "full")]
    Full,
    Short,
    Bare,
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Full
    }
}

pub fn setup_logging(log_file: Option<&PathBuf>, log_format: LogFormat) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let stdout_formatter = ProxyEventFormatter::new(log_format, true);
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(false)
        .event_format(stdout_formatter);

    if let Some(log_path) = log_file {
        let file = File::create(log_path).context("Failed to create log file")?;
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(Arc::new(file))
            .with_ansi(false)
            .event_format(ProxyEventFormatter::new(log_format, false));

        tracing_subscriber::registry()
            .with(stdout_layer.with_filter(env_filter.clone()))
            .with(file_layer.with_filter(env_filter))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(stdout_layer.with_filter(env_filter))
            .init();
    }

    Ok(())
}

struct ProxyEventFormatter {
    log_format: LogFormat,
    colorize: bool,
}

impl ProxyEventFormatter {
    fn new(log_format: LogFormat, colorize: bool) -> Self {
        Self {
            log_format,
            colorize,
        }
    }
}

impl<S, N> FormatEvent<S, N> for ProxyEventFormatter
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let timestamp = match self.log_format {
            LogFormat::Full | LogFormat::Short => Some(current_timestamp()),
            LogFormat::Bare => None,
        };

        let mut message = String::new();
        let mut visitor = MessageVisitor { buf: &mut message };
        event.record(&mut visitor);

        let metadata = event.metadata();
        let line = format_log_line(
            self.log_format,
            timestamp,
            *metadata.level(),
            metadata.target(),
            &message,
        );
        let output = if self.colorize {
            if let Some(colored) = colorize_if_needed(&line) {
                colored
            } else {
                line
            }
        } else {
            line
        };

        writeln!(writer, "{output}")
    }
}

fn current_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn format_log_line(
    log_format: LogFormat,
    timestamp: Option<String>,
    level: Level,
    target: &str,
    message: &str,
) -> String {
    match log_format {
        LogFormat::Full => {
            let ts = timestamp.unwrap_or_else(|| current_timestamp());
            format!("{ts}\t{level:>5}\t{target}\t{message}")
        }
        LogFormat::Short => {
            let ts = timestamp.unwrap_or_else(|| current_timestamp());
            format!("{ts}\t{message}")
        }
        LogFormat::Bare => message.to_string(),
    }
}

fn colorize_if_needed(line: &str) -> Option<String> {
    if is_hex_dump_line(line) {
        return Some(line.color(AnsiColors::BrightBlack).to_string());
    }

    if line.contains("] \u{2192}") {
        return Some(line.color(AnsiColors::Green).to_string());
    }

    if line.contains("] \u{2190}") {
        return Some(line.color(AnsiColors::Cyan).to_string());
    }

    None
}

fn is_hex_dump_line(line: &str) -> bool {
    if let Some(idx) = line.find("]   ") {
        let rest = &line[idx + 4..];
        if rest.len() >= 5 {
            let (hex, tail) = rest.split_at(4);
            return hex.chars().all(|c| c.is_ascii_hexdigit()) && tail.starts_with(':');
        }
    }
    false
}

struct MessageVisitor<'a> {
    buf: &'a mut String,
}

impl<'a> Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.buf, "{:?}", value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.buf.push_str(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMESTAMP: &str = "2025-11-07T16:00:09.564676Z";

    #[test]
    fn full_format_matches_default_shape() {
        let line = format_log_line(
            LogFormat::Full,
            Some(TIMESTAMP.to_string()),
            Level::INFO,
            "postgres_wire_proxy::protocol",
            "[1] ← BackendKeyData",
        );

        assert_eq!(
            line,
            "2025-11-07T16:00:09.564676Z\t INFO\tpostgres_wire_proxy::protocol\t[1] ← BackendKeyData"
        );
    }

    #[test]
    fn short_format_strips_level_and_target() {
        let line = format_log_line(
            LogFormat::Short,
            Some(TIMESTAMP.to_string()),
            Level::INFO,
            "postgres_wire_proxy::protocol",
            "[1] ← BackendKeyData",
        );
        assert_eq!(line, "2025-11-07T16:00:09.564676Z\t[1] ← BackendKeyData");
    }

    #[test]
    fn bare_format_is_message_only() {
        let line = format_log_line(
            LogFormat::Bare,
            None,
            Level::INFO,
            "postgres_wire_proxy::protocol",
            "[1] ← BackendKeyData",
        );
        assert_eq!(line, "[1] ← BackendKeyData");
    }

    #[test]
    fn client_and_server_lines_are_colored() {
        let client_line = "[1] → Query: select 1";
        let server_line = "[1] ← ReadyForQuery";
        let hex_line = "[1]   0000: de ad be ef";

        let colored_client = colorize_if_needed(client_line).expect("client line colored");
        assert!(
            colored_client.contains("\u{1b}[32m"),
            "expected green escape code"
        );

        let colored_server = colorize_if_needed(server_line).expect("server line colored");
        assert!(
            colored_server.contains("\u{1b}[36m"),
            "expected light blue (cyan) escape code"
        );

        let colored_hex = colorize_if_needed(hex_line).expect("hex line colored");
        assert!(
            colored_hex.contains("\u{1b}[90m"),
            "expected bright black escape code"
        );
    }
}
