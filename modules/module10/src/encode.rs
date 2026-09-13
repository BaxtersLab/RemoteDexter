use crate::message::*;

const VERSION_V1: u8 = 0x01;

const MSG_KEY_EVENT: u8 = 0x01;
const MSG_MOUSE_MOVE: u8 = 0x02;
const MSG_MOUSE_BUTTON: u8 = 0x03;
const MSG_MOUSE_SCROLL: u8 = 0x04;
const MSG_FOCUS_GAINED: u8 = 0x05;
const MSG_FOCUS_LOST: u8 = 0x06;
const MSG_INPUT_PAUSE: u8 = 0x07;
const MSG_INPUT_RESUME: u8 = 0x08;
const MSG_SESSION_COMMAND: u8 = 0x09;
const MSG_CAPABILITIES: u8 = 0x0A;
const MSG_TEXT_INPUT: u8 = 0x0B;

pub fn encode(msg: &InputControlMessage) -> Vec<u8> {
    let mut out = Vec::new();

    match msg {
        // Length-prefixed UTF-8. Encoded properly rather than left as a hole:
        // an arm that produced nothing would be a silent wrong encoding, and
        // one that panicked would be a stub. Note that this binary format has
        // no live users — the shipping path is JSON inside Noise — so this
        // exists to keep the format total, not because anything sends it.
        InputControlMessage::TextInput { text } => {
            out.push(MSG_TEXT_INPUT);
            out.push(VERSION_V1);
            let bytes = text.as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        InputControlMessage::KeyEvent { scan_code, action, modifiers } => {
            out.push(MSG_KEY_EVENT);
            out.push(VERSION_V1);
            out.extend_from_slice(&scan_code.to_be_bytes());
            out.push(match action {
                KeyAction::Up => 0,
                KeyAction::Down => 1,
            });
            out.push(*modifiers);
        }
        InputControlMessage::MouseMove { mode, dx, dy, abs_x, abs_y } => {
            out.push(MSG_MOUSE_MOVE);
            out.push(VERSION_V1);
            out.push(match mode {
                MouseMoveMode::Relative => 0,
                MouseMoveMode::Absolute => 1,
            });
            out.extend_from_slice(&dx.to_be_bytes());
            out.extend_from_slice(&dy.to_be_bytes());
            out.extend_from_slice(&abs_x.to_be_bytes());
            out.extend_from_slice(&abs_y.to_be_bytes());
        }
        InputControlMessage::MouseButton { button, action } => {
            out.push(MSG_MOUSE_BUTTON);
            out.push(VERSION_V1);
            out.push(*button);
            out.push(match action {
                ButtonAction::Up => 0,
                ButtonAction::Down => 1,
            });
        }
        InputControlMessage::MouseScroll { dx, dy, mode } => {
            out.push(MSG_MOUSE_SCROLL);
            out.push(VERSION_V1);
            out.extend_from_slice(&dx.to_be_bytes());
            out.extend_from_slice(&dy.to_be_bytes());
            out.push(match mode {
                ScrollMode::Lines => 0,
                ScrollMode::Pixels => 1,
            });
        }
        InputControlMessage::FocusGained => {
            out.push(MSG_FOCUS_GAINED);
            out.push(VERSION_V1);
        }
        InputControlMessage::FocusLost => {
            out.push(MSG_FOCUS_LOST);
            out.push(VERSION_V1);
        }
        InputControlMessage::InputPause => {
            out.push(MSG_INPUT_PAUSE);
            out.push(VERSION_V1);
        }
        InputControlMessage::InputResume => {
            out.push(MSG_INPUT_RESUME);
            out.push(VERSION_V1);
        }
        InputControlMessage::SessionCommand { command_type, payload } => {
            out.push(MSG_SESSION_COMMAND);
            out.push(VERSION_V1);
            out.push(*command_type);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(payload);
        }
        InputControlMessage::Capabilities { flags, max_coalesce } => {
            out.push(MSG_CAPABILITIES);
            out.push(VERSION_V1);
            out.push(*flags);
            out.push(*max_coalesce);
        }
    }

    out
}