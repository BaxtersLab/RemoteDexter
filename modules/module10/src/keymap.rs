//! Turn typed text into keystrokes.
//!
//! # Why this is on the host
//!
//! A scan code names a **physical key position**, not a character. What that
//! position produces depends on the keyboard layout in force *on the machine
//! being typed into*. So the phone cannot know it: an Android IME produces
//! text, and only the host knows which keys make that text.
//!
//! Putting the table here also means one implementation in a language the gate
//! runs, rather than a second copy in Kotlin that would drift.
//!
//! # The layout assumption, stated plainly
//!
//! **This table is US QWERTY.** On a host with a different layout the
//! punctuation will be wrong — a French AZERTY host would receive `q` for `a`.
//! That is a real limitation, not a rounding error, and the honest fix is to
//! read the host's active layout. It is not attempted here because there is no
//! portable way to ask a Wayland compositor for it, and guessing produces
//! silently wrong text, which is worse than a documented limit.
//!
//! # Refusing beats guessing
//!
//! Any character not in the table is **refused, naming the character**, rather
//! than dropped or approximated. Silently dropping characters would let a
//! password or a command arrive subtly wrong with nothing to indicate it — the
//! worst possible outcome for a remote-control tool, because the operator would
//! trust what they typed.

/// One key press, with whether Shift must be held for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keystroke {
    /// Set 1 scan code, the same encoding `InputControlMessage::KeyEvent`
    /// already carries on the wire.
    pub scan_code: u16,
    /// Whether Shift is held while this key is struck.
    pub shift: bool,
}

/// Why a text run was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextError {
    /// A character this layout cannot type.
    Unsupported {
        /// The offending character. Safe to log: it is text the operator typed
        /// on their own device, and refusing without naming it would leave them
        /// guessing which character to remove.
        ch: char,
        /// Position in the string, in characters.
        at: usize,
    },
    /// More text than one message may carry.
    TooLong {
        /// Length offered, in characters.
        len: usize,
        /// The ceiling.
        max: usize,
    },
}

/// Largest text run accepted in one message.
///
/// Bounded because each character becomes up to four kernel events, and this
/// path is remote input injection: an unbounded string is an unbounded burst
/// into the host's input stack from whatever is on the other end of the socket.
/// 256 is far more than a person types in one go and small enough that the
/// worst case is unremarkable.
pub const MAX_TEXT_CHARS: usize = 256;

/// Shift held. Set 1 code for Left Shift.
pub const SCAN_LEFT_SHIFT: u16 = 0x2A;

/// The key for one character, or `None` if this layout cannot produce it.
pub fn char_to_key(ch: char) -> Option<Keystroke> {
    let plain = |scan_code| {
        Some(Keystroke {
            scan_code,
            shift: false,
        })
    };
    let shifted = |scan_code| {
        Some(Keystroke {
            scan_code,
            shift: true,
        })
    };
    match ch {
        // Whitespace that has a key of its own.
        ' ' => plain(0x39),
        '\n' => plain(0x1C),
        '\t' => plain(0x0F),
        // A carriage return is the same key as a newline. Android soft
        // keyboards and pasted text both produce CRLF in places, and typing a
        // second Enter for the CR would insert a blank line nobody asked for.
        '\r' => None,

        'a'..='z' => plain(letter_scan(ch)),
        'A'..='Z' => shifted(letter_scan(ch.to_ascii_lowercase())),

        '1' => plain(0x02),
        '2' => plain(0x03),
        '3' => plain(0x04),
        '4' => plain(0x05),
        '5' => plain(0x06),
        '6' => plain(0x07),
        '7' => plain(0x08),
        '8' => plain(0x09),
        '9' => plain(0x0A),
        '0' => plain(0x0B),

        '!' => shifted(0x02),
        '@' => shifted(0x03),
        '#' => shifted(0x04),
        '$' => shifted(0x05),
        '%' => shifted(0x06),
        '^' => shifted(0x07),
        '&' => shifted(0x08),
        '*' => shifted(0x09),
        '(' => shifted(0x0A),
        ')' => shifted(0x0B),

        '-' => plain(0x0C),
        '_' => shifted(0x0C),
        '=' => plain(0x0D),
        '+' => shifted(0x0D),

        '[' => plain(0x1A),
        '{' => shifted(0x1A),
        ']' => plain(0x1B),
        '}' => shifted(0x1B),

        ';' => plain(0x27),
        ':' => shifted(0x27),
        '\'' => plain(0x28),
        '"' => shifted(0x28),
        '`' => plain(0x29),
        '~' => shifted(0x29),

        '\\' => plain(0x2B),
        '|' => shifted(0x2B),

        ',' => plain(0x33),
        '<' => shifted(0x33),
        '.' => plain(0x34),
        '>' => shifted(0x34),
        '/' => plain(0x35),
        '?' => shifted(0x35),

        _ => None,
    }
}

/// Set 1 code for a lowercase ASCII letter.
///
/// A table rather than arithmetic: the rows are `qwertyuiop`, `asdfghjkl`,
/// `zxcvbnm`, so scan codes do not run in alphabetical order and any formula
/// would be a coincidence waiting to break.
fn letter_scan(ch: char) -> u16 {
    match ch {
        'q' => 0x10,
        'w' => 0x11,
        'e' => 0x12,
        'r' => 0x13,
        't' => 0x14,
        'y' => 0x15,
        'u' => 0x16,
        'i' => 0x17,
        'o' => 0x18,
        'p' => 0x19,
        'a' => 0x1E,
        's' => 0x1F,
        'd' => 0x20,
        'f' => 0x21,
        'g' => 0x22,
        'h' => 0x23,
        'j' => 0x24,
        'k' => 0x25,
        'l' => 0x26,
        'z' => 0x2C,
        'x' => 0x2D,
        'c' => 0x2E,
        'v' => 0x2F,
        'b' => 0x30,
        'n' => 0x31,
        'm' => 0x32,
        _ => unreachable!("letter_scan called with a non-letter: {ch:?}"),
    }
}

/// Expand a text run into keystrokes, or refuse.
///
/// **All or nothing.** A run containing one unsupported character is refused
/// entirely rather than typed up to that point: a half-typed command or
/// password left in the host's input field is worse than nothing happening, and
/// the operator can see that nothing happened.
pub fn text_to_keystrokes(text: &str) -> Result<Vec<Keystroke>, TextError> {
    let len = text.chars().count();
    if len > MAX_TEXT_CHARS {
        return Err(TextError::TooLong {
            len,
            max: MAX_TEXT_CHARS,
        });
    }
    let mut out = Vec::with_capacity(len);
    for (at, ch) in text.chars().enumerate() {
        // A carriage return is skipped rather than refused: CRLF is text the
        // operator legitimately typed, and refusing the whole run for it would
        // make pasted text fail for a reason they cannot see.
        if ch == '\r' {
            continue;
        }
        match char_to_key(ch) {
            Some(k) => out.push(k),
            None => return Err(TextError::Unsupported { ch, at }),
        }
    }
    Ok(out)
}

/// Expand a text run into the key events that type it.
///
/// Each character becomes a **down then up** pair carrying the Shift modifier
/// when the character needs it, so the run rides
/// `InputControlMessage::KeyEvent` — the injection path that is already written
/// and tested on both platforms — instead of adding a second one that would
/// need its own modifier handling, its own ordering rules and its own bugs.
///
/// Shift is carried per keystroke rather than held across a run of capitals.
/// The injector already presses a modifier before the key-down and releases it
/// after the key-up, in separate batches, precisely so a modifier and its key
/// are not processed as simultaneous. Holding Shift across several keys would
/// mean reproducing that ordering here for a saving nobody can perceive.
pub fn text_to_messages(text: &str) -> Result<Vec<crate::message::InputControlMessage>, TextError> {
    use crate::message::{InputControlMessage, KeyAction, MOD_SHIFT};
    let strokes = text_to_keystrokes(text)?;
    let mut out = Vec::with_capacity(strokes.len() * 2);
    for k in strokes {
        let modifiers = if k.shift { MOD_SHIFT } else { 0 };
        out.push(InputControlMessage::KeyEvent {
            scan_code: k.scan_code,
            action: KeyAction::Down,
            modifiers,
        });
        out.push(InputControlMessage::KeyEvent {
            scan_code: k.scan_code,
            action: KeyAction::Up,
            modifiers,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scans(text: &str) -> Vec<(u16, bool)> {
        text_to_keystrokes(text)
            .expect("must map")
            .into_iter()
            .map(|k| (k.scan_code, k.shift))
            .collect()
    }

    #[test]
    fn lowercase_letters_need_no_shift() {
        assert_eq!(
            scans("abc"),
            vec![(0x1E, false), (0x30, false), (0x2E, false)]
        );
    }

    /// A capital is the same physical key, with Shift.
    #[test]
    fn capitals_are_the_same_key_with_shift() {
        let lower = char_to_key('a').unwrap();
        let upper = char_to_key('A').unwrap();
        assert_eq!(lower.scan_code, upper.scan_code);
        assert!(!lower.shift);
        assert!(upper.shift);
    }

    /// The whole alphabet maps, in both cases — a missing letter would be found
    /// by the operator, mid-sentence, not by a test of three characters.
    #[test]
    fn every_ascii_letter_maps_in_both_cases() {
        for ch in 'a'..='z' {
            assert!(char_to_key(ch).is_some(), "lowercase {ch} does not map");
            let upper = ch.to_ascii_uppercase();
            assert!(
                char_to_key(upper).is_some(),
                "uppercase {upper} does not map"
            );
        }
    }

    #[test]
    fn every_digit_maps_and_its_shifted_symbol_shares_the_key() {
        let pairs = [
            ('1', '!'),
            ('2', '@'),
            ('3', '#'),
            ('4', '$'),
            ('5', '%'),
            ('6', '^'),
            ('7', '&'),
            ('8', '*'),
            ('9', '('),
            ('0', ')'),
        ];
        for (digit, symbol) in pairs {
            let d = char_to_key(digit).unwrap_or_else(|| panic!("{digit} does not map"));
            let s = char_to_key(symbol).unwrap_or_else(|| panic!("{symbol} does not map"));
            assert_eq!(d.scan_code, s.scan_code, "{digit} and {symbol} are one key");
            assert!(!d.shift);
            assert!(s.shift);
        }
    }

    /// Every punctuation character reachable on a US board, since these are
    /// what a password or a shell command is made of.
    #[test]
    fn every_us_punctuation_character_maps() {
        for ch in r#"-_=+[]{};:'"`~\|,<.>/?"#.chars() {
            assert!(char_to_key(ch).is_some(), "punctuation {ch:?} does not map");
        }
    }

    #[test]
    fn space_newline_and_tab_have_their_own_keys() {
        assert_eq!(char_to_key(' ').unwrap().scan_code, 0x39);
        assert_eq!(char_to_key('\n').unwrap().scan_code, 0x1C);
        assert_eq!(char_to_key('\t').unwrap().scan_code, 0x0F);
    }

    /// CRLF must type one Enter, not two lines.
    #[test]
    fn a_carriage_return_is_skipped_rather_than_typed_twice() {
        assert_eq!(
            scans("a\r\nb"),
            vec![(0x1E, false), (0x1C, false), (0x30, false)]
        );
    }

    /// **Refusing beats guessing.** An unmappable character must not be
    /// silently dropped: a password that arrives subtly wrong, with nothing to
    /// say so, is the worst outcome here because the operator trusts what they
    /// typed.
    #[test]
    fn an_unsupported_character_is_refused_and_named() {
        assert_eq!(
            text_to_keystrokes("café"),
            Err(TextError::Unsupported { ch: 'é', at: 3 })
        );
        assert_eq!(
            text_to_keystrokes("emoji \u{1F600}"),
            Err(TextError::Unsupported {
                ch: '\u{1F600}',
                at: 6
            })
        );
    }

    /// All or nothing: a half-typed command is worse than none.
    #[test]
    fn one_bad_character_refuses_the_whole_run() {
        assert!(text_to_keystrokes("sudo rm é").is_err());
        // And nothing was produced, so the caller cannot type a prefix.
        assert!(text_to_keystrokes("sudo rm é").err().is_some());
    }

    /// Remote input injection from whatever is on the other end of the socket.
    #[test]
    fn an_oversized_run_is_refused_before_expansion() {
        let long: String = "a".repeat(MAX_TEXT_CHARS + 1);
        assert_eq!(
            text_to_keystrokes(&long),
            Err(TextError::TooLong {
                len: MAX_TEXT_CHARS + 1,
                max: MAX_TEXT_CHARS
            })
        );
        // The ceiling itself is accepted, so the bound is the stated one.
        let at_max: String = "a".repeat(MAX_TEXT_CHARS);
        assert_eq!(text_to_keystrokes(&at_max).unwrap().len(), MAX_TEXT_CHARS);
    }

    /// The length limit counts CHARACTERS, not bytes: a multi-byte character
    /// would otherwise let a shorter string be refused than the limit says.
    #[test]
    fn the_length_limit_counts_characters_not_bytes() {
        // Refused for being unsupported, NOT for length — 200 three-byte
        // characters are 600 bytes but only 200 characters.
        let text: String = "\u{20AC}".repeat(200);
        assert!(matches!(
            text_to_keystrokes(&text),
            Err(TextError::Unsupported { .. })
        ));
    }

    #[test]
    fn an_empty_run_is_accepted_and_produces_nothing() {
        assert_eq!(text_to_keystrokes(""), Ok(Vec::new()));
    }

    /// A realistic run: shell command with punctuation, mixed case and digits.
    #[test]
    fn a_realistic_command_line_maps_end_to_end() {
        let strokes = text_to_keystrokes("cd ~/Desktop && ls -la 2>&1\n").expect("must map");
        assert!(!strokes.is_empty());
        // The shifted characters really are marked shifted.
        let shifted_count = strokes.iter().filter(|k| k.shift).count();
        // ~ D & & > &  — six shifted characters in "cd ~/Desktop && ls -la 2>&1".
        assert_eq!(
            shifted_count, 6,
            "expected ~ D & & > & to be the shifted ones"
        );
    }

    /// Every character becomes a down/up pair, in order.
    #[test]
    fn text_expands_to_down_and_up_per_character() {
        use crate::message::{InputControlMessage, KeyAction};
        let msgs = text_to_messages("hi").expect("must map");
        assert_eq!(msgs.len(), 4, "two characters are four events");
        match (&msgs[0], &msgs[1]) {
            (
                InputControlMessage::KeyEvent {
                    scan_code: d,
                    action: KeyAction::Down,
                    ..
                },
                InputControlMessage::KeyEvent {
                    scan_code: u,
                    action: KeyAction::Up,
                    ..
                },
            ) => assert_eq!(d, u, "the up must release the key the down pressed"),
            other => panic!("expected a down then an up, got {other:?}"),
        }
    }

    /// A key released without its modifier would leave Shift stuck down.
    #[test]
    fn shift_is_carried_on_both_the_down_and_the_up() {
        use crate::message::{InputControlMessage, MOD_SHIFT};
        let msgs = text_to_messages("A").expect("must map");
        for m in &msgs {
            match m {
                InputControlMessage::KeyEvent { modifiers, .. } => assert_eq!(
                    *modifiers, MOD_SHIFT,
                    "both halves of a shifted keystroke must carry the modifier"
                ),
                other => panic!("expected a key event, got {other:?}"),
            }
        }
    }

    /// An unshifted character must not carry a modifier it does not need.
    #[test]
    fn an_unshifted_character_carries_no_modifier() {
        use crate::message::InputControlMessage;
        for m in text_to_messages("a").expect("must map") {
            match m {
                InputControlMessage::KeyEvent { modifiers, .. } => assert_eq!(modifiers, 0),
                other => panic!("expected a key event, got {other:?}"),
            }
        }
    }

    /// A refusal must produce no events at all, not a prefix.
    #[test]
    fn a_refused_run_expands_to_nothing() {
        assert!(text_to_messages("ok\u{00e9}").is_err());
    }

    /// Scan codes must stay inside the range `set1_to_evdev` accepts, or the
    /// injector rejects them at runtime — after the operator has typed.
    #[test]
    fn every_mapped_scan_code_is_inside_the_translatable_range() {
        for ch in ' '..='~' {
            if let Some(k) = char_to_key(ch) {
                assert!(
                    (0x01..=0x58).contains(&k.scan_code),
                    "{ch:?} maps to {:#x}, outside the Set 1 range the injector translates",
                    k.scan_code
                );
            }
        }
        assert!((0x01..=0x58).contains(&SCAN_LEFT_SHIFT));
    }

    /// Every printable ASCII character must be typable. This is the test that
    /// catches an omission the operator would otherwise find mid-password.
    #[test]
    fn every_printable_ascii_character_is_typable() {
        let mut missing = Vec::new();
        for ch in ' '..='~' {
            if char_to_key(ch).is_none() {
                missing.push(ch);
            }
        }
        assert!(
            missing.is_empty(),
            "unmappable printable ASCII: {missing:?}"
        );
    }
}
