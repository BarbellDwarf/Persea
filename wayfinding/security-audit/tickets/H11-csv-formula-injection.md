# Ticket: CSV export formula injection

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/db.rs:1665` — `csv_escape_field` escapes only `,`/`"`/`\n`, not leading `=+-@`. Reachable via poweruser-controlled fields (`hostname`, `entry_display_name`, `address_book_folder`, `created_by` through ad-hoc session creation) flowing into `report_sessions_csv` (`src/api/reports.rs:213-238`, gated only by `poweruser`).

## Fix

Per OWASP CSV-injection guidance, prefix any field starting with `=+-@\t\r` with a single quote or tab before writing. Update `csv_escape_field`:

```rust
fn csv_escape_field(field: &str) -> String {
    let trimmed = field.trim_start();
    let prefix = if trimmed.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        "'"
    } else {
        ""
    };
    // existing escaping logic
}
```

## Files

- `src/db.rs:1665` — `csv_escape_field`
- `src/api/reports.rs:213-238` — `report_sessions_csv`

## Deliverable

Fields starting with formula characters are prefixed with a single quote. CSV export still opens correctly in Excel/Sheets. `cargo check` passes.
