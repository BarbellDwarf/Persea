# Ticket: No default recording retention/purge limit

wayfinder:task
Priority: P3
Phase: Low

## Finding

`src/recording.rs` — `rotate`/`rotate_per_entry` only acts when `max_recordings`/`max_disk_percent` is explicitly configured. Unlimited by default. Recordings accumulate until disk is full.

## Fix

Ship a sane default cap. Add to config defaults:
```toml
[recording]
max_recordings = 1000
max_disk_percent = 80
```

Update `config.rs` defaults so these values are always set, even when not in the config file. The rotation logic then applies automatically.

## Files

- `src/config.rs` — recording defaults
- `config.example.toml` — documentation

## Deliverable

Default recording cap of 1000 recordings or 80% disk. Rotation runs automatically. `cargo check` passes.
