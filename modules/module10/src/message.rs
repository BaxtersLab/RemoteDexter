/// Modifier bit flags, shared by every backend and the Android client.
///
/// These lived in THREE places — `inject_linux`, `inject` (Windows) and the
/// client — each carrying a comment saying it must match the others, which is
/// the arrangement in which they eventually do not. One definition, imported by
/// the backends, is the version that cannot drift.
pub const MOD_SHIFT: u8 = 0x01;
/// See [`MOD_SHIFT`].
pub const MOD_CTRL: u8 = 0x02;
/// See [`MOD_SHIFT`].
pub const MOD_ALT: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum InputControlMessage {
    /// Type a run of text.
    ///
    /// The phone sends TEXT, not keys, because a scan code names a physical key
    /// position and only the host knows which position produces which
    /// character. Expanded here by `keymap::text_to_messages` into ordinary
    /// `KeyEvent`s, so it rides the injection path that is already proven
    /// rather than adding a second one.
    TextInput {
        /// Bounded and validated by `keymap::text_to_keystrokes`; a run
        /// containing a character this layout cannot type is refused whole.
        text: String,
    },
    KeyEvent {
        scan_code: u16,
        action: KeyAction,
        modifiers: u8,
    },
    MouseMove {
        mode: MouseMoveMode,
        dx: i32,
        dy: i32,
        abs_x: u32,
        abs_y: u32,
    },
    MouseButton {
        button: u8,
        action: ButtonAction,
    },
    MouseScroll {
        dx: i32,
        dy: i32,
        mode: ScrollMode,
    },
    FocusGained,
    FocusLost,
    InputPause,
    InputResume,
    SessionCommand {
        command_type: u8,
        payload: Vec<u8>,
    },
    Capabilities {
        flags: u8,
        max_coalesce: u8,
    },
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum KeyAction {
    Up,
    Down,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ButtonAction {
    Up,
    Down,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum MouseMoveMode {
    Relative,
    Absolute,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ScrollMode {
    Lines,
    Pixels,
}