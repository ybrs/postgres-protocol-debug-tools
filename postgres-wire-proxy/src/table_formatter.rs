use std::io::{self, IsTerminal};
use std::sync::Mutex;

/// Represents field metadata from RowDescription
#[derive(Clone, Debug)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: String,
}

/// Table formatting state for a single result set
pub struct TableFormatter {
    fields: Vec<FieldInfo>,
    column_widths: Vec<usize>,
    header_printed: bool,
    terminal_width: Option<usize>,
}

impl TableFormatter {
    pub fn new(fields: Vec<FieldInfo>) -> Self {
        // Use fixed column width of 15 characters for simplicity and alignment
        const FIXED_COL_WIDTH: usize = 15;

        let column_widths = vec![FIXED_COL_WIDTH; fields.len()];

        Self {
            fields,
            column_widths,
            header_printed: false,
            terminal_width: None, // Not using dynamic width anymore
        }
    }

    /// Print the table header with column names
    pub fn print_header(&mut self, client_addr: &str) {
        if self.header_printed {
            return;
        }

        let parts = self.format_row(
            &self.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            &self.column_widths
        );

        // Print header
        tracing::info!("[{}] ┌{}┐", client_addr, parts.separator);
        tracing::info!("[{}] │{}│", client_addr, parts.data);
        tracing::info!("[{}] ├{}┤", client_addr, parts.separator);

        self.header_printed = true;
    }

    /// Print a data row
    pub fn print_row(&mut self, values: &[String], client_addr: &str) {
        // Ensure header is printed first
        if !self.header_printed {
            self.print_header(client_addr);
        }

        // Use fixed column widths - no dynamic adjustment
        let value_refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        let parts = self.format_row(&value_refs, &self.column_widths);
        tracing::info!("[{}] │{}│", client_addr, parts.data);
    }

    /// Print the table footer
    pub fn print_footer(&self, client_addr: &str) {
        if !self.header_printed {
            return;
        }

        let separator = self.column_widths
            .iter()
            .map(|w| "─".repeat(*w))
            .collect::<Vec<_>>()
            .join("┴");

        tracing::info!("[{}] └{}┘", client_addr, separator);
    }

    /// Format a row with the given values and widths
    fn format_row(&self, values: &[&str], widths: &[usize]) -> FormattedParts {
        let mut cells = Vec::new();

        for (i, &value) in values.iter().enumerate() {
            let width = widths.get(i).copied().unwrap_or(10);
            let cell = pad_or_truncate(value, width);
            cells.push(cell);
        }

        let data = cells.join("│");
        let separator = widths
            .iter()
            .map(|w| "─".repeat(*w))
            .collect::<Vec<_>>()
            .join("┬");

        FormattedParts { data, separator }
    }
}

struct FormattedParts {
    data: String,
    separator: String,
}

/// Detect terminal width, returning None if not detectable
fn detect_terminal_width() -> Option<usize> {
    // Try to get terminal size using termsize crate or environment variable
    // For now, we'll use a simple approach with COLUMNS env var or default
    if let Ok(cols) = std::env::var("COLUMNS") {
        cols.parse().ok()
    } else {
        // Default to 120 if we can't detect
        Some(120)
    }
}

/// Calculate the display width of a string (handling Unicode)
fn unicode_display_width(s: &str) -> usize {
    // For simplicity, use char count. In production, you'd use unicode-width crate
    s.chars().count()
}

/// Pad or truncate a string to fit the desired width
fn pad_or_truncate(s: &str, width: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let char_count = chars.len();

    if char_count <= width {
        // Pad with spaces to reach the exact width
        let padding = " ".repeat(width - char_count);
        format!("{}{}", s, padding)
    } else {
        // Truncate and add ellipsis
        if width >= 3 {
            let truncated: String = chars.iter().take(width - 3).collect();
            format!("{}...", truncated)
        } else {
            chars.iter().take(width).collect()
        }
    }
}

/// Per-client state for table formatting
pub struct TableState {
    table_mode: bool,
    current_formatter: Mutex<Option<TableFormatter>>,
}

impl TableState {
    pub fn new(table_mode: bool) -> Self {
        Self {
            table_mode,
            current_formatter: Mutex::new(None),
        }
    }

    pub fn is_table_mode(&self) -> bool {
        self.table_mode
    }

    pub fn set_row_description(&self, fields: Vec<FieldInfo>) {
        if self.table_mode {
            let mut formatter = self.current_formatter.lock().unwrap();
            *formatter = Some(TableFormatter::new(fields));
        }
    }

    pub fn print_data_row(&self, values: &[String], client_addr: &str) {
        if !self.table_mode {
            return;
        }

        let mut formatter = self.current_formatter.lock().unwrap();
        if let Some(ref mut f) = *formatter {
            f.print_row(values, client_addr);
        }
    }

    pub fn finish_result_set(&self, client_addr: &str) {
        if !self.table_mode {
            return;
        }

        let mut formatter = self.current_formatter.lock().unwrap();
        if let Some(ref f) = *formatter {
            f.print_footer(client_addr);
        }
        *formatter = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_or_truncate_pads_short_strings() {
        assert_eq!(pad_or_truncate("hello", 10), "hello     ");
    }

    #[test]
    fn pad_or_truncate_preserves_exact_width() {
        assert_eq!(pad_or_truncate("exactly10!", 10), "exactly10!");
    }

    #[test]
    fn pad_or_truncate_truncates_long_strings() {
        let result = pad_or_truncate("this is a very long string", 10);
        assert_eq!(result.len(), 10);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn unicode_width_counts_chars() {
        assert_eq!(unicode_display_width("hello"), 5);
        assert_eq!(unicode_display_width("hello👋"), 6);
    }

    #[test]
    fn table_formatter_initializes_with_fields() {
        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
                type_name: "int4".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
                type_name: "text".to_string(),
            },
        ];

        let formatter = TableFormatter::new(fields.clone());
        assert_eq!(formatter.fields.len(), 2);
        assert_eq!(formatter.column_widths[0], 15); // fixed width
        assert_eq!(formatter.column_widths[1], 15); // fixed width
    }

    #[test]
    fn table_formatter_uses_fixed_widths() {
        let fields = vec![FieldInfo {
            name: "col".to_string(),
            type_name: "text".to_string(),
        }];

        let mut formatter = TableFormatter::new(fields);
        assert_eq!(formatter.column_widths[0], 15); // Fixed width

        // Add rows - width should remain fixed
        formatter.print_row(&["short".to_string()], "test");
        assert_eq!(formatter.column_widths[0], 15);

        formatter.print_row(&["much longer value".to_string()], "test");
        assert_eq!(formatter.column_widths[0], 15); // Still fixed
    }

    #[test]
    fn table_state_only_formats_when_enabled() {
        let state = TableState::new(false);
        assert!(!state.is_table_mode());

        // Should not panic even when called without setup
        state.print_data_row(&["value".to_string()], "test");
        state.finish_result_set("test");
    }

    #[test]
    fn table_state_formats_when_enabled() {
        let state = TableState::new(true);
        assert!(state.is_table_mode());

        let fields = vec![FieldInfo {
            name: "test_col".to_string(),
            type_name: "int4".to_string(),
        }];

        state.set_row_description(fields);
        state.print_data_row(&["123".to_string()], "test");
        state.finish_result_set("test");
    }

    #[test]
    fn table_formatter_handles_null_values() {
        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
                type_name: "int4".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
                type_name: "text".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields);
        formatter.print_row(&["1".to_string(), "NULL".to_string()], "test");
        formatter.print_row(&["2".to_string(), "Alice".to_string()], "test");
        formatter.print_footer("test");
    }

    #[test]
    fn table_formatter_handles_wide_columns() {
        let fields = vec![
            FieldInfo {
                name: "short".to_string(),
                type_name: "text".to_string(),
            },
            FieldInfo {
                name: "very_long_column_name".to_string(),
                type_name: "text".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields);
        assert_eq!(formatter.column_widths[1], 15); // fixed width

        formatter.print_row(&["a".to_string(), "b".to_string()], "test");
        formatter.print_row(
            &[
                "x".to_string(),
                "This is an extremely long value that exceeds the column width".to_string(),
            ],
            "test",
        );
        formatter.print_footer("test");
    }

    #[test]
    fn table_formatter_handles_empty_values() {
        let fields = vec![FieldInfo {
            name: "col".to_string(),
            type_name: "text".to_string(),
        }];

        let mut formatter = TableFormatter::new(fields);
        formatter.print_row(&["".to_string()], "test");
        formatter.print_row(&["value".to_string()], "test");
        formatter.print_footer("test");
    }

    #[test]
    fn table_formatter_handles_multiple_columns() {
        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
                type_name: "int4".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
                type_name: "text".to_string(),
            },
            FieldInfo {
                name: "email".to_string(),
                type_name: "text".to_string(),
            },
            FieldInfo {
                name: "age".to_string(),
                type_name: "int4".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields);
        formatter.print_row(
            &[
                "1".to_string(),
                "Alice".to_string(),
                "alice@example.com".to_string(),
                "30".to_string(),
            ],
            "test",
        );
        formatter.print_row(
            &[
                "2".to_string(),
                "Bob".to_string(),
                "bob@example.com".to_string(),
                "25".to_string(),
            ],
            "test",
        );
        formatter.print_footer("test");
    }

    #[test]
    fn pad_or_truncate_handles_very_short_width() {
        // Width 3 results in "..." (ellipsis)
        assert_eq!(pad_or_truncate("hello", 3), "...");
        // Width less than string length but >= 3 adds ellipsis
        assert_eq!(pad_or_truncate("hello", 4), "h...");
        // Width equal or greater than string doesn't truncate
        assert_eq!(pad_or_truncate("hi", 2), "hi");
        assert_eq!(pad_or_truncate("hi", 3), "hi ");
    }

    #[test]
    fn table_formatter_maintains_fixed_column_alignment() {
        let fields = vec![
            FieldInfo {
                name: "num".to_string(),
                type_name: "int4".to_string(),
            },
            FieldInfo {
                name: "text".to_string(),
                type_name: "text".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields);

        // First row with short values
        formatter.print_row(&["1".to_string(), "a".to_string()], "test");
        let widths_after_first = formatter.column_widths.clone();

        // Second row with longer values
        formatter.print_row(&["12345".to_string(), "longer text".to_string()], "test");

        // Column widths should remain fixed
        assert_eq!(formatter.column_widths[0], widths_after_first[0]);
        assert_eq!(formatter.column_widths[1], widths_after_first[1]);
        assert_eq!(formatter.column_widths[0], 15);
        assert_eq!(formatter.column_widths[1], 15);
    }
}
