use module10::*;

#[test]
fn test_encode_decode_key_event() {
    let msg = InputControlMessage::KeyEvent {
        scan_code: 42,
        action: KeyAction::Down,
        modifiers: 1,
    };
    let encoded = encode::encode(&msg);
    let decoded = decode::decode(&encoded).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn test_encode_decode_mouse_move() {
    let msg = InputControlMessage::MouseMove {
        mode: MouseMoveMode::Relative,
        dx: 10,
        dy: -5,
        abs_x: 0,
        abs_y: 0,
    };
    let encoded = encode::encode(&msg);
    let decoded = decode::decode(&encoded).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn test_encode_decode_capabilities() {
    let msg = InputControlMessage::Capabilities {
        flags: 7,
        max_coalesce: 5,
    };
    let encoded = encode::encode(&msg);
    let decoded = decode::decode(&encoded).unwrap();
    assert_eq!(msg, decoded);
}