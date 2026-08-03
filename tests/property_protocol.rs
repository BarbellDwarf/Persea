use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics_on_any_utf8(input in "\\PC*") {
        let _ = persea::protocol::Instruction::parse(&input);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes(input in prop::collection::vec(0u8..=255, 0..1000)) {
        let s = String::from_utf8_lossy(&input);
        let _ = persea::protocol::Instruction::parse(&s);
    }

    #[test]
    fn encode_then_parse_roundtrip(opcode in "[a-zA-Z]{1,20}", args in prop::collection::vec("[a-zA-Z0-9]{0,50}", 0..10)) {
        let instr = persea::protocol::Instruction::new(&opcode, args.clone());
        let encoded = instr.encode();
        let parsed = persea::protocol::Instruction::parse(&encoded).unwrap();
        prop_assert_eq!(parsed.opcode, opcode);
        prop_assert_eq!(parsed.args, args);
    }

    #[test]
    fn parser_never_panics_on_any_utf8(input in "\\PC*") {
        let mut parser = persea::protocol::InstructionParser::new();
        let _ = parser.receive(&input);
    }
}
