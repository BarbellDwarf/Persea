# Rust Protocol Parser Fuzzing Findings

Fuzz targets for `src/protocol.rs` — persea's Guacamole wire-format
parser and streaming instruction parser.

## Setup

- **Fuzzer**: cargo-fuzz (libFuzzer) with nightly Rust
- **Targets**: `protocol_parse` (single instruction), `protocol_stream` (streaming)

Run: `cargo +nightly fuzz run protocol_parse` / `cargo +nightly fuzz run protocol_stream`

## Results

**Run date**: 2026-02-07
**Iterations**: ~52.8 million total (49.5M parse + 3.3M stream, 5 min each)

### Fixed: UTF-8 char boundary panic

**Crash input**: `4.smze,1.\xc7\xbb\x00`
**Severity**: Denial of service (panic/unwrap)

`Instruction::parse()` sliced a string at a byte offset derived from
the length prefix without checking `is_char_boundary()`. When the
length pointed into the middle of a multi-byte UTF-8 character (e.g.,
the 2-byte sequence `\xc7\xbb`), Rust panicked.

**Fix**: Added `remaining.is_char_boundary(len)` check before slicing,
returning `ParseError::Truncated` for invalid boundaries. Fixed in v0.1.3.

### No other issues

After the fix, both fuzz targets ran 52.8M iterations with zero
additional crashes or panics.

## guacd parser fuzzing

See `../fuzz-guacd/` for the C-side guacd protocol parser fuzzer.
