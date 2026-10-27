use std::io::{self, IsTerminal};
use std::sync::Mutex;

/// Represents field metadata from RowDescription
#[derive(Clone, Debug)]
pub struct FieldInfo {
    pub name: String,
}

/// Column width used when dynamic sizing is off.
const FIXED_COL_WIDTH: usize = 15;

/// Narrowest a dynamically sized column may get: a couple of characters plus
/// the truncation ellipsis.
const MIN_COL_WIDTH: usize = 5;

/// Assumed terminal width when the output is a terminal but `COLUMNS` is unset.
const DEFAULT_TERMINAL_WIDTH: usize = 120;

/// Table formatting state for a single result set
pub struct TableFormatter {
    fields: Vec<FieldInfo>,
    column_widths: Vec<usize>,
    header_printed: bool,
    /// Size columns to their content instead of the fixed width. Rows are then
    /// held back until the result set is complete, because the widest cell of a
    /// column is only known once every row has arrived.
    dynamic_width: bool,
    pending_rows: Vec<Vec<String>>,
}

impl TableFormatter {
    pub fn new(fields: Vec<FieldInfo>, dynamic_width: bool) -> Self {
        let column_widths = vec![FIXED_COL_WIDTH; fields.len()];

        Self {
            fields,
            column_widths,
            header_printed: false,
            dynamic_width,
            pending_rows: Vec::new(),
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
        if self.dynamic_width {
            // Held until the result set is complete: the widths depend on every
            // row, including the ones still to come.
            self.pending_rows.push(values.to_vec());
            return;
        }

        // Ensure header is printed first
        if !self.header_printed {
            self.print_header(client_addr);
        }

        let value_refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        let parts = self.format_row(&value_refs, &self.column_widths);
        tracing::info!("[{}] │{}│", client_addr, parts.data);
    }

    /// Print the table footer
    pub fn print_footer(&mut self, client_addr: &str) {
        if self.dynamic_width {
            self.flush_dynamic(client_addr);
            return;
        }

        if !self.header_printed {
            return;
        }

        tracing::info!(
            "[{}] └{}┘",
            client_addr,
            footer_separator(&self.column_widths)
        );
    }

    /// Print the buffered rows now that the widest cell of each column is known.
    fn flush_dynamic(&mut self, client_addr: &str) {
        if self.pending_rows.is_empty() {
            return;
        }

        self.column_widths = self.dynamic_column_widths(detect_terminal_width());
        self.header_printed = false;
        self.print_header(client_addr);

        for row in std::mem::take(&mut self.pending_rows) {
            let values: Vec<&str> = row.iter().map(String::as_str).collect();
            let parts = self.format_row(&values, &self.column_widths);
            tracing::info!("[{}] │{}│", client_addr, parts.data);
        }

        tracing::info!(
            "[{}] └{}┘",
            client_addr,
            footer_separator(&self.column_widths)
        );
    }

    /// Column widths that fit the header and every buffered value, capped so the
    /// rendered table fits `limit` characters.
    fn dynamic_column_widths(&self, limit: Option<usize>) -> Vec<usize> {
        let mut widths: Vec<usize> = self
            .fields
            .iter()
            .map(|f| unicode_display_width(&f.name).max(MIN_COL_WIDTH))
            .collect();

        for row in &self.pending_rows {
            for (i, value) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(i) {
                    *width = (*width).max(unicode_display_width(value));
                }
            }
        }

        fit_widths(&mut widths, limit);
        widths
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

/// The box-drawing line under the last row.
fn footer_separator(widths: &[usize]) -> String {
    widths
        .iter()
        .map(|w| "─".repeat(*w))
        .collect::<Vec<_>>()
        .join("┴")
}

/// Shrink `widths` until the rendered table fits `limit` characters.
///
/// A row of n columns renders as `sum(widths) + n + 1` characters: one border
/// per column, plus the two ends. The widest column is shaved one character at a
/// time, so the columns that need the room keep it and none goes below
/// [`MIN_COL_WIDTH`].
fn fit_widths(widths: &mut [usize], limit: Option<usize>) {
    let Some(limit) = limit else {
        return;
    };
    let Some(budget) = limit.checked_sub(widths.len() + 1) else {
        return;
    };

    while widths.iter().sum::<usize>() > budget {
        let Some(widest) = widths
            .iter()
            .enumerate()
            .filter(|(_, width)| **width > MIN_COL_WIDTH)
            .max_by_key(|(_, width)| **width)
            .map(|(index, _)| index)
        else {
            break; // Every column is at the floor; the table cannot get narrower.
        };
        widths[widest] -= 1;
    }
}

/// Width of the terminal the table is printed to, if it is knowable.
///
/// `COLUMNS` wins: a shell sets it, and it is the one part a test can control.
/// When stdout is not a terminal - a log file, a pipe - there is no width to
/// respect, so the table is allowed to be as wide as its content.
fn detect_terminal_width() -> Option<usize> {
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(cols) = cols.trim().parse::<usize>() {
            if cols > 0 {
                return Some(cols);
            }
        }
    }

    io::stdout().is_terminal().then_some(DEFAULT_TERMINAL_WIDTH)
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
    dynamic_width: bool,
    current_formatter: Mutex<Option<TableFormatter>>,
}

impl TableState {
    pub fn new(table_mode: bool, dynamic_width: bool) -> Self {
        Self {
            table_mode,
            dynamic_width,
            current_formatter: Mutex::new(None),
        }
    }

    pub fn is_table_mode(&self) -> bool {
        self.table_mode
    }

    pub fn set_row_description(&self, fields: Vec<FieldInfo>) {
        if self.table_mode {
            let mut formatter = self.current_formatter.lock().unwrap();
            *formatter = Some(TableFormatter::new(fields, self.dynamic_width));
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
        if let Some(ref mut f) = *formatter {
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
            },
            FieldInfo {
                name: "name".to_string(),
            },
        ];

        let formatter = TableFormatter::new(fields.clone(), false);
        assert_eq!(formatter.fields.len(), 2);
        assert_eq!(formatter.column_widths[0], 15); // fixed width
        assert_eq!(formatter.column_widths[1], 15); // fixed width
    }

    #[test]
    fn table_formatter_uses_fixed_widths() {
        let fields = vec![FieldInfo {
            name: "col".to_string(),
        }];

        let mut formatter = TableFormatter::new(fields, false);
        assert_eq!(formatter.column_widths[0], 15); // Fixed width

        // Add rows - width should remain fixed
        formatter.print_row(&["short".to_string()], "test");
        assert_eq!(formatter.column_widths[0], 15);

        formatter.print_row(&["much longer value".to_string()], "test");
        assert_eq!(formatter.column_widths[0], 15); // Still fixed
    }

    #[test]
    fn table_state_only_formats_when_enabled() {
        let state = TableState::new(false, false);
        assert!(!state.is_table_mode());

        // Should not panic even when called without setup
        state.print_data_row(&["value".to_string()], "test");
        state.finish_result_set("test");
    }

    #[test]
    fn table_state_formats_when_enabled() {
        let state = TableState::new(true, false);
        assert!(state.is_table_mode());

        let fields = vec![FieldInfo {
            name: "test_col".to_string(),
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
            },
            FieldInfo {
                name: "name".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields, false);
        formatter.print_row(&["1".to_string(), "NULL".to_string()], "test");
        formatter.print_row(&["2".to_string(), "Alice".to_string()], "test");
        formatter.print_footer("test");
    }

    #[test]
    fn table_formatter_handles_wide_columns() {
        let fields = vec![
            FieldInfo {
                name: "short".to_string(),
            },
            FieldInfo {
                name: "very_long_column_name".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields, false);
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
        }];

        let mut formatter = TableFormatter::new(fields, false);
        formatter.print_row(&["".to_string()], "test");
        formatter.print_row(&["value".to_string()], "test");
        formatter.print_footer("test");
    }

    #[test]
    fn table_formatter_handles_multiple_columns() {
        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
            },
            FieldInfo {
                name: "email".to_string(),
            },
            FieldInfo {
                name: "age".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields, false);
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
            },
            FieldInfo {
                name: "text".to_string(),
            },
        ];

        let mut formatter = TableFormatter::new(fields, false);

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

    #[test]
    fn rendered_rows_keep_their_width_when_values_are_long() {
        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
            },
        ];

        let formatter = TableFormatter::new(fields, false);
        let widths = formatter.column_widths.clone();
        let short = formatter.format_row(&["1", "'Bob'"], &widths);
        let long = formatter.format_row(&["2", "'0123456789abcdefghij0123456789'"], &widths);

        assert_eq!(
            formatter.column_widths,
            vec![15, 15],
            "columns must not grow to fit their content"
        );
        assert_eq!(short.data, format!("1{}│'Bob'{}", " ".repeat(14), " ".repeat(10)));
        assert_eq!(long.data, format!("2{}│'0123456789a...", " ".repeat(14)));
        assert_eq!(
            long.data.chars().count(),
            short.data.chars().count(),
            "a longer value must not widen the rendered row"
        );
    }

    fn text_fields() -> Vec<FieldInfo> {
        vec![
            FieldInfo {
                name: "id".to_string(),
            },
            FieldInfo {
                name: "name".to_string(),
            },
        ]
    }

    #[test]
    fn dynamic_columns_grow_to_fit_the_widest_value() {
        let mut formatter = TableFormatter::new(text_fields(), true);
        formatter.print_row(&["1".to_string(), "'Bob'".to_string()], "test");
        formatter.print_row(
            &["2".to_string(), "'0123456789abcdefghij0123456789'".to_string()],
            "test",
        );

        // Nothing is rendered until the result set ends: every row is held back.
        assert_eq!(formatter.pending_rows.len(), 2);

        let widths = formatter.dynamic_column_widths(None);
        assert_eq!(widths, vec![5, 32], "wide enough for the longest value");
    }

    #[test]
    fn dynamic_columns_fit_the_header_when_values_are_shorter() {
        let fields = vec![FieldInfo {
            name: "a_rather_long_column_name".to_string(),
        }];
        let mut formatter = TableFormatter::new(fields, true);
        formatter.print_row(&["'x'".to_string()], "test");

        assert_eq!(
            formatter.dynamic_column_widths(None),
            vec!["a_rather_long_column_name".len()],
            "the header is part of the content"
        );
    }

    #[test]
    fn dynamic_columns_never_go_below_the_minimum() {
        let mut formatter = TableFormatter::new(text_fields(), true);
        formatter.print_row(&["1".to_string(), "''".to_string()], "test");

        assert_eq!(formatter.dynamic_column_widths(None), vec![5, 5]);
    }

    #[test]
    fn dynamic_columns_shrink_to_the_terminal_width() {
        let mut formatter = TableFormatter::new(text_fields(), true);
        formatter.print_row(
            &[
                "1".to_string(),
                format!("'{}'", "x".repeat(60)),
            ],
            "test",
        );

        let widths = formatter.dynamic_column_widths(Some(40));
        let total: usize = widths.iter().sum::<usize>() + widths.len() + 1;
        assert!(
            total <= 40,
            "a {total} character row does not fit 40 columns: {widths:?}"
        );
        assert!(
            widths[1] > widths[0],
            "the column with more content keeps more room: {widths:?}"
        );
    }

    #[test]
    fn dynamic_columns_shrink_until_the_table_fits() {
        let mut widths = vec![40, 40, 40];
        fit_widths(&mut widths, Some(20));

        // Three columns plus four borders leave a budget of 16.
        assert_eq!(widths.iter().sum::<usize>(), 16);
        assert!(widths.iter().all(|width| *width >= MIN_COL_WIDTH));
    }

    #[test]
    fn dynamic_columns_stop_shrinking_at_the_minimum_width() {
        // A budget of 11 cannot hold three columns of five: the floor wins.
        let mut widths = vec![40, 40, 40];
        fit_widths(&mut widths, Some(15));

        assert_eq!(widths, vec![MIN_COL_WIDTH; 3]);
    }

    #[test]
    fn rendered_dynamic_rows_are_all_the_same_width() {
        let mut formatter = TableFormatter::new(text_fields(), true);
        formatter.print_row(&["1".to_string(), "'Bob'".to_string()], "test");
        formatter.print_row(
            &["2".to_string(), "'a much longer value'".to_string()],
            "test",
        );
        let widths = formatter.dynamic_column_widths(None);

        let short = formatter.format_row(&["1", "'Bob'"], &widths);
        let long = formatter.format_row(&["2", "'a much longer value'"], &widths);

        assert_eq!(short.data.chars().count(), long.data.chars().count());
        assert_eq!(
            short.data,
            format!(
                "1{}│'Bob'{}",
                " ".repeat(widths[0] - 1),
                " ".repeat(widths[1] - 5)
            )
        );
        assert!(
            long.data.ends_with("'a much longer value'"),
            "a value inside the column is not truncated: {}",
            long.data
        );
    }

    #[test]
    fn dynamic_width_still_truncates_values_wider_than_the_column() {
        let mut formatter = TableFormatter::new(text_fields(), true);
        formatter.print_row(
            &[
                "1".to_string(),
                format!("'{}'", "y".repeat(60)),
            ],
            "test",
        );

        let widths = formatter.dynamic_column_widths(Some(20));
        let row = formatter.format_row(
            &[
                "1",
                &format!("'{}'", "y".repeat(60)),
            ],
            &widths,
        );

        assert!(
            row.data.ends_with("..."),
            "value must be cut to the column: {}",
            row.data
        );
        assert_eq!(row.data.chars().count(), widths.iter().sum::<usize>() + 1);
    }
}
