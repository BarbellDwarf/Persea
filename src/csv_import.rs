//! Pure CSV parsing and validation for address book CSV imports.
//!
//! No axum / DB dependencies: the tokenizer is a small hand-rolled state
//! machine (the `csv` crate is not a dependency) that handles quoted fields,
//! escaped quotes (`""`), embedded newlines, and `\r\n` line endings.
//!
//! Row numbering convention: data rows are 1-based (the first row after the
//! header is row 1). `CsvError.row == 0` marks a file-level error (bad or
//! missing header, unterminated quote).

use std::collections::HashSet;

/// Fixed column names, in order, for the CSV header and template.
///
/// Optional TRAILING columns (beyond the 9 fixed ones) are custom-field
/// columns whose names must match the configured custom field definitions
/// exactly — see [`parse_rows`]. The `name` column holds the friendly name;
/// the stored identifier is `slugify(name)` (applied by the importer).
pub const HEADERS: [&str; 9] = [
    "name",
    "protocol",
    "hostname",
    "port",
    "username",
    "password",
    "folder",
    "allowed_groups",
    "description",
];

/// The pre-T08 template header (had a `display_name` column). Recognized so
/// the rejection error can point the user at the current template instead of
/// a generic column mismatch.
pub const LEGACY_HEADERS: [&str; 10] = [
    "name",
    "protocol",
    "hostname",
    "port",
    "username",
    "password",
    "folder",
    "display_name",
    "allowed_groups",
    "description",
];

/// Protocols accepted by the address book.
pub const VALID_PROTOCOLS: [&str; 7] = ["ssh", "rdp", "vnc", "spice", "web", "vdi", "proxmox"];

/// A single validated connection row ready to be imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Friendly name; the importer slugifies it into the stored identifier.
    pub name: String,
    /// Lowercased protocol: ssh, rdp, vnc, spice, web, vdi, or proxmox.
    pub protocol: String,
    /// Target hostname or IP. Empty for web/vdi/proxmox rows that use a
    /// URL or container image instead.
    pub hostname: String,
    /// `None` when the port column is empty.
    pub port: Option<u16>,
    /// Username for the connection; may be empty.
    pub username: String,
    /// Password for the connection; may be empty. The importer stores it
    /// encrypted.
    pub password: String,
    /// Normalized folder path, e.g. `Production/Web` or `""` for the root.
    pub folder: String,
    /// Trimmed, de-duplicated group names (in file order).
    pub allowed_groups: Vec<String>,
    /// Free-form description/notes (may be empty).
    pub description: String,
    /// Custom field values: (configured column name → trimmed cell value)
    /// for every trailing column in the file header. Empty values are kept
    /// verbatim; the importer decides what to persist.
    pub custom_fields: Vec<(String, String)>,
}

/// A per-row or file-level parse problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvError {
    /// 1-based data row index; `0` for file-level errors (header/quoting).
    pub row: usize,
    /// Human-readable description of the problem.
    pub message: String,
}

/// Outcome of parsing a CSV body. Invalid rows are reported in `errors`,
/// in-file duplicates of `(folder, name)` are listed in `skipped`, and
/// `rows` holds the remaining rows ready for import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseResult {
    /// Validated rows ready for import, in file order.
    pub rows: Vec<Row>,
    /// 1-based row indices dropped as in-file duplicates of (folder, name).
    pub skipped: Vec<usize>,
    /// Per-row problems, each carrying its 1-based row index.
    pub errors: Vec<CsvError>,
}

/// Parse and validate a CSV document.
///
/// The first record must be a header matching [`HEADERS`] (case-insensitive,
/// optional UTF-8 BOM, columns may be trimmed) followed by 0..N trailing
/// columns that match the configured custom field names EXACTLY (trimmed,
/// case-sensitive). The legacy 10-column header (with `display_name`) is
/// rejected with a pointer to the current template. Blank lines are ignored.
/// Returns `Err` only for file-level problems (empty input, invalid header,
/// unterminated quoted field); per-row problems are collected in the result.
pub fn parse_rows(input: &str, custom_fields: &[String]) -> Result<ParseResult, CsvError> {
    let records = tokenize(input)?;
    let Some(header) = records.first() else {
        return Err(CsvError {
            row: 0,
            message: "empty CSV: no header row found".into(),
        });
    };

    // Raw (trimmed, case-preserving) header fields: the 9 fixed columns are
    // matched case-insensitively, custom-field columns case-sensitively.
    let raw_header: Vec<String> = header.iter().map(|f| f.trim().to_string()).collect();
    let mut normalized: Vec<String> = raw_header.iter().map(|f| f.to_ascii_lowercase()).collect();
    if let Some(first) = normalized.first_mut() {
        *first = first.trim_start_matches('\u{feff}').to_string();
    }

    // Recognize the old template so the error can point at the new one.
    if normalized.len() == LEGACY_HEADERS.len()
        && normalized
            .iter()
            .zip(LEGACY_HEADERS.iter())
            .all(|(a, b)| a == b)
    {
        return Err(CsvError {
            row: 0,
            message: "invalid header: this file uses the OLD 10-column template with a \
                      'display_name' column; the template has changed — download the current \
                      one from /api/addressbook/import-template and re-export your data"
                .into(),
        });
    }

    for (i, expected) in HEADERS.iter().enumerate() {
        if normalized.get(i).map(String::as_str) != Some(expected) {
            return Err(CsvError {
                row: 0,
                message: format!(
                    "invalid header: column {} should be '{}' but is '{}' (template: {})",
                    i + 1,
                    expected,
                    normalized.get(i).map(String::as_str).unwrap_or("(missing)"),
                    HEADERS.join(",")
                ),
            });
        }
    }

    // Trailing columns are custom-field columns; each must match a configured
    // definition exactly (trimmed, case-sensitive).
    let mut custom_cols: Vec<String> = Vec::new();
    for (i, col) in raw_header.iter().skip(HEADERS.len()).enumerate() {
        let name = col.trim();
        if !custom_fields.iter().any(|d| d == name) {
            return Err(CsvError {
                row: 0,
                message: format!(
                    "invalid header: column {} '{}' is not a configured custom field{}",
                    HEADERS.len() + i + 1,
                    name,
                    if custom_fields.is_empty() {
                        " (none are configured)".to_string()
                    } else {
                        format!(" (configured: {})", custom_fields.join(", "))
                    }
                ),
            });
        }
        custom_cols.push(name.to_string());
    }

    let mut result = ParseResult::default();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let header_len = HEADERS.len() + custom_cols.len();

    for (idx, record) in records.iter().skip(1).enumerate() {
        let row_index = idx + 1;
        if record.iter().all(|f| f.is_empty()) {
            continue;
        }
        if record.len() > header_len {
            result.errors.push(CsvError {
                row: row_index,
                message: format!(
                    "too many columns: got {}, expected {}",
                    record.len(),
                    header_len
                ),
            });
            continue;
        }

        let mut fields: Vec<String> = record.clone();
        fields.resize(header_len, String::new());

        let name = fields[0].trim().to_string();
        let protocol = fields[1].trim().to_ascii_lowercase();
        let hostname = fields[2].trim().to_string();
        let port = parse_port(&fields[3]);
        let username = fields[4].trim().to_string();
        let password = fields[5].to_string();
        let folder = normalize_folder(&fields[6]);
        let allowed_groups = parse_groups(&fields[7]);
        let description = fields[8].trim().to_string();

        let mut messages = Vec::new();
        if let Err(msg) = &port {
            messages.push(msg.clone());
        }
        if let Err(msg) = validate_row(
            &name,
            &protocol,
            &hostname,
            port.as_ref().ok().copied().flatten(),
        ) {
            messages.push(msg);
        }
        if !messages.is_empty() {
            result.errors.push(CsvError {
                row: row_index,
                message: messages.join("; "),
            });
            continue;
        }

        let key = (folder.clone(), name.clone());
        if !seen.insert(key) {
            result.skipped.push(row_index);
            continue;
        }

        let custom_values = custom_cols
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let value = fields.get(HEADERS.len() + i).cloned().unwrap_or_default();
                (col.clone(), value.trim().to_string())
            })
            .collect();

        result.rows.push(Row {
            name,
            protocol,
            hostname,
            port: port.unwrap(),
            username,
            password,
            folder,
            allowed_groups,
            description,
            custom_fields: custom_values,
        });
    }

    Ok(result)
}

/// Validate a single row's core fields, mirroring the JSON import contract.
/// `port` is already `u16`-typed by the caller (serde/CSV port parsing).
pub fn validate_row(
    name: &str,
    protocol: &str,
    hostname: &str,
    _port: Option<u16>,
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("name is required".into());
    }
    let protocol = protocol.trim().to_ascii_lowercase();
    if !VALID_PROTOCOLS.contains(&protocol.as_str()) {
        return Err(format!(
            "invalid protocol '{}' (must be one of {})",
            protocol,
            VALID_PROTOCOLS.join(", ")
        ));
    }
    // Web/VDI/Proxmox entries use url / container_image / proxmox_url
    // instead of a plain hostname.
    if hostname.trim().is_empty() && !matches!(protocol.as_str(), "web" | "vdi" | "proxmox") {
        return Err(format!("hostname is required for protocol '{}'", protocol));
    }
    Ok(())
}

/// Normalize a folder path: trim, strip leading/trailing slashes.
/// `""` (or `"/"`) means the scope root.
pub fn normalize_folder(path: &str) -> String {
    path.trim().trim_matches('/').to_string()
}

/// Split a comma-separated group list, trimming entries and dropping empties
/// and duplicates (first occurrence wins).
fn parse_groups(input: &str) -> Vec<String> {
    let mut groups: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for g in input.split(',') {
        let g = g.trim();
        if g.is_empty() || !seen.insert(g.to_string()) {
            continue;
        }
        groups.push(g.to_string());
    }
    groups
}

/// Parse the port column: empty -> `Ok(None)`, otherwise a `u16`.
fn parse_port(input: &str) -> Result<Option<u16>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    input
        .parse::<u16>()
        .map(Some)
        .map_err(|_| format!("invalid port '{}'", input))
}

/// Render the downloadable template: header row plus one example row.
///
/// When custom fields are configured their columns are appended (with an
/// example value) so the template stays in sync with the importer.
pub fn render_template(custom_fields: &[String]) -> String {
    let mut header = HEADERS.join(",");
    let mut example = "My Server,ssh,10.0.0.1,22,root,secret,Production/Web,\"group1,group2\",Production web server"
        .to_string();
    for f in custom_fields {
        header.push(',');
        header.push_str(f);
        example.push_str(",Example value");
    }
    format!("{}\n{}\n", header, example)
}

/// Tokenize a CSV document into records of fields (RFC-4180 style).
///
/// Handles: quoted fields, `""` escapes inside quotes, embedded newlines and
/// commas inside quotes, `\r\n` / `\n` / lone `\r` record endings.
fn tokenize(input: &str) -> Result<Vec<Vec<String>>, CsvError> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut record_started = false;
    let mut chars = input.chars().peekable();

    loop {
        let Some(c) = chars.next() else {
            if in_quotes {
                return Err(CsvError {
                    row: records.len(),
                    message: "unterminated quoted field".into(),
                });
            }
            if record_started || !record.is_empty() || !field.is_empty() {
                record.push(field);
                records.push(record);
            }
            break;
        };
        match c {
            '"' if in_quotes => {
                if matches!(chars.peek(), Some('"')) {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' if field.is_empty() => {
                in_quotes = true;
                record_started = true;
            }
            '"' => field.push('"'),
            ',' if !in_quotes => {
                record.push(std::mem::take(&mut field));
                record_started = true;
            }
            '\n' if !in_quotes => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                record_started = false;
            }
            '\r' if !in_quotes => {
                if matches!(chars.peek(), Some('\n')) {
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                record_started = false;
            }
            other => {
                field.push(other);
                record_started = true;
            }
        }
    }

    Ok(records)
}
