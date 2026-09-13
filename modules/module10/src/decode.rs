use crate::message::*;
use crate::errors::InputControlError;

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

pub fn decode(bytes: &[u8]) -> Result<InputControlMessage, InputControlError> {
    if bytes.len() < 2 {
        return Err(InputControlError::Malformed);
    }

    let msg_type = bytes[0];
    let version = bytes[1];

    if version != VERSION_V1 {
        return Err(InputControlError::UnsupportedVersion(version));
    }

    match msg_type {
        MSG_KEY_EVENT => {
            if bytes.len() != 6 {
                return Err(InputControlError::Malformed);
            }
            let scan_code = u16::from_be_bytes([bytes[2], bytes[3]]);
            let action = match bytes[4] {
                0 => KeyAction::Up,
                1 => KeyAction::Down,
                _ => return Err(InputControlError::Malformed),
            };
            let modifiers = bytes[5];
            Ok(InputControlMessage::KeyEvent { scan_code, action, modifiers })
        }
        MSG_MOUSE_MOVE => {
            if bytes.len() != 19 {
                return Err(InputControlError::Malformed);
            }
            let mode = match bytes[2] {
                0 => MouseMoveMode::Relative,
                1 => MouseMoveMode::Absolute,
                _ => return Err(InputControlError::Malformed),
            };
            let dx = i32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
            let dy = i32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
            let abs_x = u32::from_be_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
            let abs_y = u32::from_be_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
            Ok(InputControlMessage::MouseMove { mode, dx, dy, abs_x, abs_y })
        }
        MSG_MOUSE_BUTTON => {
            if bytes.len() != 4 {
                return Err(InputControlError::Malformed);
            }
            let button = bytes[2];
            let action = match bytes[3] {
                0 => ButtonAction::Up,
                1 => ButtonAction::Down,
                _ => return Err(InputControlError::Malformed),
            };
            Ok(InputControlMessage::MouseButton { button, action })
        }
        MSG_MOUSE_SCROLL => {
            if bytes.len() != 11 {
                return Err(InputControlError::Malformed);
            }
            let dx = i32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let dy = i32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
            let mode = match bytes[10] {
                0 => ScrollMode::Lines,
                1 => ScrollMode::Pixels,
                _ => return Err(InputControlError::Malformed),
            };
            Ok(InputControlMessage::MouseScroll { dx, dy, mode })
        }
        MSG_FOCUS_GAINED => {
            if bytes.len() != 2 {
                return Err(InputControlError::Malformed);
            }
            Ok(InputControlMessage::FocusGained)
        }
        MSG_FOCUS_LOST => {
            if bytes.len() != 2 {
                return Err(InputControlError::Malformed);
            }
            Ok(InputControlMessage::FocusLost)
        }
        MSG_INPUT_PAUSE => {
            if bytes.len() != 2 {
                return Err(InputControlError::Malformed);
            }
            Ok(InputControlMessage::InputPause)
        }
        MSG_INPUT_RESUME => {
            if bytes.len() != 2 {
                return Err(InputControlError::Malformed);
            }
            Ok(InputControlMessage::InputResume)
        }
        MSG_SESSION_COMMAND => {
            if bytes.len() < 7 {
                return Err(InputControlError::Malformed);
            }
            let command_type = bytes[2];
            let payload_len = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as usize;
            if bytes.len() != 7 + payload_len {
                return Err(InputControlError::Malformed);
            }
            let payload = bytes[7..].to_vec();
            Ok(InputControlMessage::SessionCommand { command_type, payload })
        }
        MSG_TEXT_INPUT => {
            // Length must be exact, not a minimum: trailing bytes after a
            // declared length are the same ambiguity Block 10 removed from the
            // frame parser, and accepting them here would reintroduce it.
            if bytes.len() < 4 {
                return Err(InputControlError::Malformed);
            }
            let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            if bytes.len() != 4 + len {
                return Err(InputControlError::Malformed);
            }
            let text = std::str::from_utf8(&bytes[4..])
                .map_err(|_| InputControlError::Malformed)?
                .to_string();
            Ok(InputControlMessage::TextInput { text })
        }
        MSG_CAPABILITIES => {
            if bytes.len() != 4 {
                return Err(InputControlError::Malformed);
            }
            let flags = bytes[2];
            let max_coalesce = bytes[3];
            Ok(InputControlMessage::Capabilities { flags, max_coalesce })
        }
        _ => Err(InputControlError::UnknownMessageType(msg_type)),
    }
}