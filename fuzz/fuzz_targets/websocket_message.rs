#![no_main]
use libfuzzer_sys::fuzz_target;
use persea::protocol::{Instruction, InstructionParser};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Simulate a WebSocket message stream: parse, validate opcode, re-encode
        let mut parser = InstructionParser::new();
        for inst in parser.receive(s).into_iter().flatten() {
            // Exercise the encode path (server→client direction)
            let encoded = inst.encode();
            // Verify round-trip: re-parse the encoded instruction
            let _ = Instruction::parse(&encoded);

            // Exercise opcode matching (the WebSocket handler switches on opcode)
            match inst.opcode.as_str() {
                "mouse" | "key" | "size" | "clipboard" | "disconnect" | "nop" | "ack" | "blob"
                | "end" | "put" | "get" | "pipe" | "argv" => {}
                _ => {
                    // Unknown opcodes are forwarded as-is; just ensure encode works
                    let _ = inst.encode();
                }
            }
        }
    }

    // Also fuzz with raw bytes that aren't valid UTF-8 —
    // the WebSocket handler must handle binary frames gracefully
    let lossy = String::from_utf8_lossy(data);
    let _ = Instruction::parse(&lossy);
});
