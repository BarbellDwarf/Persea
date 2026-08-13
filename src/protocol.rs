//! Guacamole protocol instruction encoding and decoding.
//!
//! Wire format: `LENGTH.ELEMENT,LENGTH.ELEMENT,...;`
//! Example: `4.size,3.800,3.600;`

use std::fmt;

/// Maximum protocol buffer size in bytes (1 MiB). If the parser's buffer
/// exceeds this, it is cleared to prevent unbounded memory growth from a
/// misbehaving or malicious peer.
const MAX_PROTOCOL_BUFFER_LEN: usize = 1_048_576;

/// A single Guacamole protocol instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    /// Instruction name, e.g. `"size"`, `"select"`, `"connect"`.
    pub opcode: String,
    /// Positional arguments for the instruction, in wire order.
    pub args: Vec<String>,
}

impl Instruction {
    /// Build an instruction from an opcode and its argument list.
    pub fn new(opcode: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            opcode: opcode.into(),
            args,
        }
    }

    /// Encode this instruction into Guacamole wire format.
    pub fn encode(&self) -> String {
        let mut out = encode_element(&self.opcode);
        for arg in &self.args {
            out.push(',');
            out.push_str(&encode_element(arg));
        }
        out.push(';');
        out
    }

    /// Parse a single instruction from a complete instruction string (including the trailing `;`).
    pub fn parse(data: &str) -> Result<Self, ParseError> {
        let data = data.trim_end_matches(';');
        if data.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut elements = Vec::new();
        let mut remaining = data;

        loop {
            // Parse length
            let dot_pos = remaining.find('.').ok_or(ParseError::MalformedElement)?;
            let len: usize = remaining[..dot_pos]
                .parse()
                .map_err(|_| ParseError::InvalidLength)?;
            remaining = &remaining[dot_pos + 1..];

            // Extract element value (length is in bytes per Guacamole spec)
            if remaining.len() < len {
                return Err(ParseError::Truncated);
            }
            if !remaining.is_char_boundary(len) {
                return Err(ParseError::Truncated);
            }
            elements.push(remaining[..len].to_string());
            remaining = &remaining[len..];

            // Check for separator or end
            if remaining.is_empty() {
                break;
            }
            if remaining.starts_with(',') {
                remaining = &remaining[1..];
            } else {
                return Err(ParseError::UnexpectedChar);
            }
        }

        if elements.is_empty() {
            return Err(ParseError::Empty);
        }

        let opcode = elements.remove(0);
        Ok(Instruction {
            opcode,
            args: elements,
        })
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

fn encode_element(s: &str) -> String {
    // Length is the number of UTF-8 bytes (matching guacamole-common-js behavior
    // for the server-side protocol; the JS side counts UTF-16 code units but
    // guacd uses byte length).
    format!("{}.{}", s.len(), s)
}

#[derive(Debug, PartialEq)]
#[must_use]
/// Why a Guacamole instruction could not be parsed from wire format.
pub enum ParseError {
    /// The instruction contained no elements at all (empty input or a bare `;`).
    Empty,
    /// An element was missing its `.` length separator.
    MalformedElement,
    /// The length prefix was not a valid `usize` (non-numeric, negative, or overflowing).
    InvalidLength,
    /// The declared length ran past the end of the data, or cut through the middle of a UTF-8 character.
    Truncated,
    /// A byte appeared where the parser expected `,` or the end of the instruction.
    UnexpectedChar,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty instruction"),
            ParseError::MalformedElement => write!(f, "malformed element (missing '.')"),
            ParseError::InvalidLength => write!(f, "invalid length prefix"),
            ParseError::Truncated => write!(f, "instruction truncated"),
            ParseError::UnexpectedChar => write!(f, "unexpected character in instruction"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Fast-path threshold: buffers at or above this size always run the full
/// scan. Small buffers are the SSH terminal common case (keystrokes, short
/// text), where the structural walk below avoids the byte-by-byte element
/// walk; large buffers are RDP display data (JPEG tiles), where the full
/// scan stays authoritative.
const BOUNDARY_FAST_PATH_MAX: usize = 1024;

/// Find the byte offset just past the last complete Guacamole instruction in
/// `buf`. Returns `None` if no complete instruction is present.
///
/// Walks element-by-element using the wire format's length prefix (which
/// counts UTF-8 characters per `guac_utf8_strlen` in libguac), so element
/// data containing literal `;` characters (clipboard text, text streams)
/// does not produce a false boundary.
///
/// On the first malformed byte it returns the boundary discovered so far
/// rather than scanning the rest of the buffer.
pub fn last_instruction_boundary(buf: &[u8]) -> Option<usize> {
    // Fast path: small buffers ending in `;` (the overwhelmingly common
    // case of one complete SSH terminal instruction) skip the per-byte
    // element walk. The length prefixes let the structural walk skip each
    // element's data in O(1), so complete small instructions are resolved
    // without touching their bytes. The walk only claims a boundary when
    // the buffer is pure ASCII (length prefixes count characters, not
    // bytes) and the declared lengths account for the buffer exactly —
    // a truncated tail (element whose declared length runs past the end,
    // or a trailing `;` that is really data inside an unfinished element)
    // always falls through to the full scan below.
    if buf.len() < BOUNDARY_FAST_PATH_MAX
        && buf.last() == Some(&b';')
        && buf.is_ascii()
        && fast_instruction_boundary(buf).is_some()
    {
        return Some(buf.len());
    }

    let mut last_end: Option<usize> = None;
    let mut pos = 0usize;

    loop {
        // Each instruction is 1+ comma-separated elements, terminated by ';'.
        loop {
            // Length prefix: ASCII decimal digits up to the '.' separator.
            let len_start = pos;
            while pos < buf.len() && buf[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos == len_start || pos >= buf.len() || buf[pos] != b'.' {
                return last_end;
            }
            let len: usize = match std::str::from_utf8(&buf[len_start..pos])
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(n) => n,
                None => return last_end,
            };
            pos += 1; // skip '.'

            // Skip `len` UTF-8 characters of element data.
            let mut chars_skipped = 0;
            while chars_skipped < len {
                if pos >= buf.len() {
                    return last_end; // truncated mid-element
                }
                let b = buf[pos];
                let char_len = if b < 0x80 {
                    1
                } else if b < 0xC0 {
                    // Lone continuation byte — input is malformed UTF-8.
                    // Bail out with whatever boundary we've already proven.
                    return last_end;
                } else if b < 0xE0 {
                    2
                } else if b < 0xF0 {
                    3
                } else {
                    4
                };
                if pos + char_len > buf.len() {
                    return last_end; // truncated multibyte
                }
                pos += char_len;
                chars_skipped += 1;
            }

            // Element terminator.
            if pos >= buf.len() {
                return last_end;
            }
            match buf[pos] {
                b',' => {
                    pos += 1;
                    // Continue inner loop: next element of this instruction.
                }
                b';' => {
                    pos += 1;
                    last_end = Some(pos);
                    break; // Out of element loop; start scanning next instruction.
                }
                _ => return last_end,
            }
        }

        // Falls through on `;`: continue 'instructions to scan more.
        if pos >= buf.len() {
            return last_end;
        }
    }
}

/// Structural walk used by the [`last_instruction_boundary`] fast path.
///
/// For a pure-ASCII buffer, skips each element's data via its declared
/// length (no byte-by-byte scan) and requires the instruction sequence to
/// end exactly at the final `;`. Returns `Some(buf.len())` when the buffer
/// is exactly one or more complete instructions; `None` for anything
/// truncated or malformed (the caller then runs the full scan).
///
/// For ASCII input this walk is equivalent to the full scan: lengths are
/// in characters and characters are one byte, so the arithmetic lands on
/// the same separators. Incomplete input never satisfies the length
/// accounting (the declared lengths run past the end), so a trailing `;`
/// inside an unfinished element can never be mistaken for a terminator.
fn fast_instruction_boundary(buf: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    loop {
        let len_start = pos;
        while pos < buf.len() && buf[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == len_start || pos >= buf.len() || buf[pos] != b'.' {
            return None;
        }
        let len: usize = std::str::from_utf8(&buf[len_start..pos])
            .ok()?
            .parse()
            .ok()?;
        pos += 1; // skip '.'
        pos = pos.checked_add(len)?; // skip element data (ASCII: bytes == chars)
        if pos >= buf.len() {
            return None; // declared length runs past the end — truncated
        }
        match buf[pos] {
            b',' => pos += 1,
            b';' => {
                pos += 1;
                if pos == buf.len() {
                    return Some(buf.len());
                }
                // More instructions follow; keep walking.
            }
            _ => return None,
        }
    }
}

/// Streaming parser that accumulates data and yields complete instructions.
///
/// Uses `bytes::BytesMut` internally to avoid repeated String allocations
/// when slicing the buffer after extracting instructions.
pub struct InstructionParser {
    buffer: bytes::BytesMut,
}

impl Default for InstructionParser {
    fn default() -> Self {
        Self {
            buffer: bytes::BytesMut::with_capacity(8192),
        }
    }
}

impl InstructionParser {
    /// Create an empty parser, ready to receive data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed data into the parser and return any complete instructions.
    pub fn receive(&mut self, data: &str) -> Vec<Result<Instruction, ParseError>> {
        self.buffer.extend_from_slice(data.as_bytes());

        if self.buffer.len() > MAX_PROTOCOL_BUFFER_LEN {
            self.buffer.clear();
            return vec![];
        }

        let mut results = Vec::new();

        while let Some(semi_pos) = self.buffer.iter().position(|&b| b == b';') {
            let instruction_bytes = self.buffer.split_to(semi_pos + 1);
            // Strip trailing ';' before parsing
            let instr_slice = &instruction_bytes[..instruction_bytes.len() - 1];
            let instruction_str = match std::str::from_utf8(instr_slice) {
                Ok(s) => s,
                Err(_) => {
                    results.push(Err(ParseError::MalformedElement));
                    continue;
                }
            };
            results.push(Instruction::parse(instruction_str));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple() {
        let inst = Instruction::new("size", vec!["800".into(), "600".into()]);
        assert_eq!(inst.encode(), "4.size,3.800,3.600;");
    }

    #[test]
    fn test_encode_no_args() {
        let inst = Instruction::new("nop", vec![]);
        assert_eq!(inst.encode(), "3.nop;");
    }

    #[test]
    fn test_encode_select() {
        let inst = Instruction::new("select", vec!["ssh".into()]);
        assert_eq!(inst.encode(), "6.select,3.ssh;");
    }

    #[test]
    fn test_parse_simple() {
        let inst = Instruction::parse("4.size,3.800,3.600").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_with_semicolon() {
        let inst = Instruction::parse("4.size,3.800,3.600;").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_no_args() {
        let inst = Instruction::parse("3.nop").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert!(inst.args.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let original = Instruction::new(
            "connect",
            vec![
                "10.0.0.5".into(),
                "22".into(),
                "admin".into(),
                "password123".into(),
            ],
        );
        let encoded = original.encode();
        let parsed = Instruction::parse(&encoded).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_streaming_parser() {
        let mut parser = InstructionParser::new();

        // Feed partial data
        let results = parser.receive("4.size,3.80");
        assert!(results.is_empty());

        // Complete the instruction and start another
        let results = parser.receive("0,3.600;3.nop;");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().opcode, "size");
        assert_eq!(results[1].as_ref().unwrap().opcode, "nop");
    }

    // ── Adversarial parser cases ───────────────────────────────────────────
    // guacd is a trust boundary: even under compromise, the persea parser
    // must refuse to panic, must reject malformed frames cleanly, and must
    // bound memory. Every negative case here should produce a ParseError or
    // be dropped by the 1 MiB buffer cap — never a panic or OOM.

    #[test]
    fn parse_rejects_length_longer_than_data() {
        // Claims 10 bytes but only 3 are present.
        let err = Instruction::parse("10.abc").unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_rejects_non_numeric_length() {
        let err = Instruction::parse("x.size").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_negative_length() {
        // `-1` is not valid usize — must be rejected, not cast.
        let err = Instruction::parse("-1.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_overflow_length() {
        // 2^65 overflows usize on every platform and must be a clean error.
        let err = Instruction::parse("36893488147419103232.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_missing_dot() {
        let err = Instruction::parse("4size").unwrap_err();
        assert!(matches!(err, ParseError::MalformedElement));
    }

    #[test]
    fn parse_rejects_unexpected_separator() {
        // After the element body we must see `,` or end. A bare letter
        // should produce UnexpectedChar, not silently continue.
        let err = Instruction::parse("4.sizeX3.800").unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedChar));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(
            Instruction::parse("").unwrap_err(),
            ParseError::Empty
        ));
        assert!(matches!(
            Instruction::parse(";").unwrap_err(),
            ParseError::Empty
        ));
    }

    #[test]
    fn parse_rejects_split_multibyte_char() {
        // '€' is three bytes (E2 82 AC). Claiming length 2 would split the
        // char on a non-boundary — parser must reject rather than panic.
        let bad = "2.€";
        let err = Instruction::parse(bad).unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_accepts_correct_multibyte_length() {
        // Correct byte-length for '€' is 3.
        let inst = Instruction::parse("3.€").unwrap();
        assert_eq!(inst.opcode, "€");
    }

    #[test]
    fn parse_accepts_zero_length_element() {
        let inst = Instruction::parse("3.nop,0.,3.foo").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert_eq!(inst.args, vec!["", "foo"]);
    }

    #[test]
    fn parse_accepts_embedded_semicolon_within_length() {
        // Length includes the `;` so it's part of the element, not a
        // terminator. The caller's framing must respect length; this test
        // proves parse() honours the length over the semicolon.
        let inst = Instruction::parse("5.a;b;c").unwrap();
        assert_eq!(inst.opcode, "a;b;c");
    }

    #[test]
    fn streaming_parser_caps_buffer_at_1_mib() {
        // Feed > 1 MiB in a single receive with no terminator. The buffer
        // must clear in-place rather than grow unbounded, and the call
        // must return cleanly without panicking. After the clear, a fresh
        // well-formed frame parses normally.
        let mut parser = InstructionParser::new();
        let huge = "x".repeat(1_100_000);
        let out = parser.receive(&huge);
        // Over-cap input is dropped entirely (no partial instruction yield).
        assert!(out.is_empty());
        // Fresh input parses correctly — buffer is empty, no residue.
        let out2 = parser.receive("3.nop;");
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_split_at_every_boundary() {
        // Feed a well-formed frame byte-by-byte; the parser must assemble
        // correctly regardless of where chunks break.
        let full = "4.size,3.800,3.600;3.nop;";
        let mut parser = InstructionParser::new();
        let mut all = Vec::new();
        for ch in full.chars() {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            all.extend(parser.receive(s));
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_ref().unwrap().opcode, "size");
        assert_eq!(all[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_emits_error_for_malformed_frame() {
        // A malformed-but-terminated frame yields a Result::Err, not a panic.
        let mut parser = InstructionParser::new();
        let out = parser.receive("not-a-valid-instruction;3.nop;");
        assert_eq!(out.len(), 2);
        assert!(out[0].is_err());
        assert_eq!(out[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn boundary_empty_buffer() {
        assert_eq!(last_instruction_boundary(b""), None);
    }

    #[test]
    fn boundary_complete_instruction() {
        let s = b"4.size,3.800,3.600;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_partial_no_terminator() {
        assert_eq!(last_instruction_boundary(b"4.size,3.80"), None);
    }

    #[test]
    fn boundary_two_instructions_first_complete() {
        let s = b"4.size,3.800,3.600;3.foo";
        assert_eq!(last_instruction_boundary(s), Some(19));
    }

    #[test]
    fn boundary_two_instructions_both_complete() {
        let s = b"4.size,3.800,3.600;3.nop;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_ignores_semicolon_inside_element_value() {
        // Clipboard text containing `;`: the embedded `;` MUST NOT be treated
        // as an instruction terminator. Length prefix 11 covers "hello;world".
        let s = b"9.clipboard,1.0,11.hello;world;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_partial_when_split_inside_element_data() {
        // Reader landed mid-clipboard-element: only "hello;" of the 11-char
        // value is present. The trailing `;` is data, not a terminator.
        let s = b"9.clipboard,1.0,11.hello;";
        assert_eq!(last_instruction_boundary(s), None);
    }

    #[test]
    fn boundary_empty_opcode_ping() {
        // `0.,4.ping,13.1234567890123;` — empty opcode (length 0) is valid.
        let s = b"0.,4.ping,13.1234567890123;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_handles_utf8_multibyte_in_element() {
        // "café" — 4 UTF-8 chars, 5 bytes. Length prefix counts characters.
        let s = "9.clipboard,1.0,4.café;".as_bytes();
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_truncated_mid_multibyte() {
        // "9.clipboard,1.0,4.caf" + first byte of "é" only — must not advance.
        let mut s = b"9.clipboard,1.0,4.caf".to_vec();
        s.push(0xC3); // first byte of `é` (UTF-8 0xC3 0xA9)
        assert_eq!(last_instruction_boundary(&s), None);
    }

    #[test]
    fn boundary_returns_last_complete_when_trailing_garbage() {
        // First instruction is complete; what follows is malformed. We
        // should still report the first boundary so the proxy can flush it.
        let s = b"3.nop;garbage";
        assert_eq!(last_instruction_boundary(s), Some(6));
    }

    use proptest::prelude::*;
    fn valid_instruction_strategy() -> impl Strategy<Value = Instruction> {
        (
            "[a-z]{1,12}",
            proptest::collection::vec("[a-zA-Z0-9._/: -]{0,64}", 0..6),
        )
            .prop_map(|(opcode, args)| Instruction::new(opcode, args))
    }
    proptest! {
        #[test]
        fn proptest_roundtrip_encode_decode(ins in valid_instruction_strategy()) {
            let encoded = ins.encode();
            let parsed = Instruction::parse(&encoded).expect("encode then parse should never fail");
            prop_assert_eq!(&ins, &parsed);
        }
        #[test]
        fn proptest_length_prefix_matches_content(opcode in "[a-z]{1,12}", args in proptest::collection::vec("[a-zA-Z0-9._/: -]{0,64}", 0..6)) {
            let ins = Instruction::new(opcode, args);
            let encoded = ins.encode();
            let dot = encoded.find('.').expect("must have dot");
            let len: usize = encoded[..dot].parse().expect("length must be numeric");
            let after_dot = &encoded[dot + 1..];
            prop_assert!(after_dot.len() >= len);
            prop_assert_eq!(after_dot[..len].as_bytes(), ins.opcode.as_bytes());
        }
        #[test]
        fn proptest_invalid_input_is_error_not_panic(input in ".*") {
            let _ = Instruction::parse(&input);
        }
    }
}
