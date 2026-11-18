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

/// Largest text run accepted in one message: a paragraph.
///
/// It was 256, "far more than a person types in one go" — which held for a
/// command line and failed for the thing the operator actually composes on a
/// phone. Their report (RD-TEXT-1): typing stops at about two sentences.
/// 2,000 characters is a long paragraph, roughly 300 words.
///
/// Still bounded, for two reasons that have not changed:
///
/// * This is remote input injection. An unbounded string is an unbounded burst
///   into the host's input stack from whatever is on the other end of the
///   socket, so the run is also typed in paced batches
///   ([`TEXT_BATCH_EVENTS`]), never in one burst.
/// * It has to fit one INPUT message. The shipping client frames every
///   `input_event` as `wire::Kind::InputV1`, at most 4 KiB — deliberately the
///   tightest envelope on the link. Ordinary prose of 2,000 characters encodes
///   to about 2.1 KB. Text dense with characters JSON escapes (quotes,
///   backslashes, slashes, line breaks: two bytes each) or with multi-byte
///   characters can pass 4 KiB under this count, so the phone ALSO measures
///   the encoded command and refuses an over-size one itself, before its
///   compose field clears: the client's native loop drops an unframeable
///   command after `sendCommand` has already said yes. Both limits are pinned
///   in the shared contract and asserted on each side.
///
/// The phone enforces the same number, counted the same way (Unicode scalar
/// values, Enter included), so this refusal is only ever reached by a client
/// that does not.
pub const MAX_TEXT_CHARS: usize = 2000;

/// Kernel events injected per batch of a text run, at most, before the host
/// yields.
///
/// A paragraph is thousands of kernel events, and the reader on the other side
/// of `/dev/uinput` — the compositor's libinput — gets its own **64-event**
/// evdev buffer per device (`EVDEV_MIN_BUFFER_SIZE`; a keyboard's packet hint
/// is too small to raise it). One slot is the ring's gap, so 63 usable. If the
/// writer gets that far ahead the kernel discards the backlog and reports
/// `SYN_DROPPED`: characters vanish from the middle of the text with nothing
/// on either end saying so. Measured in BaxtersVMHarness on 2026-11-17: the
/// same 2,000-character paragraph in one burst delivered 574 to 1,778 of its
/// 4,274 key events to a reader polling every 200 µs.
///
/// **Twenty, so THREE batches fit (60 of 63).** The first design sized a batch
/// to fill the buffer — seven shifted keystrokes, 56 events — and the VM showed
/// why that is not enough: a reader that misses a single pause has two batches
/// waiting, 112 events, and two runs in three lost one. At twenty the reader
/// may miss two consecutive pauses and lose nothing. Batches are cut by event
/// cost ([`kernel_events`]), not keystroke count, so ordinary lower-case text
/// is not paced as if every key were shifted. Pinned by
/// `three_batches_fit_the_evdev_buffer` here and, on a real kernel, by
/// `live_text_batches_fit_the_readers_evdev_buffer`.
pub const TEXT_BATCH_EVENTS: usize = 20;

/// The kernel's per-reader evdev buffer, in events, for a uinput keyboard.
/// One slot of the ring is always empty, so what is waiting must stay below
/// this.
pub const EVDEV_READER_BUFFER_EVENTS: usize = 64;

/// Kernel events one keystroke becomes on Linux: `inject_linux` emits each
/// modifier and the key in its own frame, each ending in `SYN_REPORT` — so
/// `(1 + modifiers) * 2` for the press and the same for the release. Four for
/// a plain key, eight with Shift.
pub fn kernel_events(key: &TypedKey) -> usize {
    use crate::message::InputControlMessage;
    [&key.down, &key.up]
        .iter()
        .map(|m| match m {
            InputControlMessage::KeyEvent { modifiers, .. } => {
                (1 + modifiers.count_ones() as usize) * 2
            }
            // A plan is built only of key events; anything else costs a frame.
            _ => 2,
        })
        .sum()
}

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
    Ok(plan_keystrokes(text)?.into_iter().map(|(k, _)| k).collect())
}

/// Each keystroke with how many characters of `text` are consumed once it has
/// been struck — the one place the run is validated, so every caller gets the
/// same all-or-nothing answer.
///
/// The count is of the SOURCE text, not of keystrokes: a skipped `\r` is
/// consumed too. That is what lets a run stopped part-way say exactly where it
/// stopped in the text the operator wrote.
fn plan_keystrokes(text: &str) -> Result<Vec<(Keystroke, usize)>, TextError> {
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
            Some(k) => out.push((k, at + 1)),
            None => return Err(TextError::Unsupported { ch, at }),
        }
    }
    Ok(out)
}

/// One keystroke of a text run, ready to inject: the press, the release, and
/// how far into the source text the run has got once both have landed.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedKey {
    /// The key-down, carrying Shift when the character needs it.
    pub down: crate::message::InputControlMessage,
    /// The matching key-up, carrying the same modifiers so Shift is released.
    pub up: crate::message::InputControlMessage,
    /// Characters of the source text consumed through this keystroke.
    pub chars_through: usize,
}

/// A whole text run, validated, as keystrokes to be injected in batches.
#[derive(Debug, Clone, PartialEq)]
pub struct TextPlan {
    /// Every keystroke, in order.
    pub keys: Vec<TypedKey>,
    /// Characters in the source text. A run that finishes has consumed all of
    /// them, including any trailing `\r` that produced no keystroke.
    pub total_chars: usize,
}

impl TextPlan {
    /// The keystrokes in order, cut into batches of at most
    /// [`TEXT_BATCH_EVENTS`] kernel events. Greedy: a batch takes keystrokes
    /// until the next would not fit. A keystroke is never split across
    /// batches, so a pause never falls between a key's press and its release.
    pub fn batches(&self) -> Vec<&[TypedKey]> {
        let mut out = Vec::new();
        let mut start = 0;
        let mut cost = 0;
        for (i, key) in self.keys.iter().enumerate() {
            let k = kernel_events(key);
            if cost + k > TEXT_BATCH_EVENTS && i > start {
                out.push(&self.keys[start..i]);
                start = i;
                cost = 0;
            }
            cost += k;
        }
        if start < self.keys.len() {
            out.push(&self.keys[start..]);
        }
        out
    }
}

/// Validate a whole text run and lay it out for paced injection.
///
/// **Validation is complete before anything is returned.** An unsupported
/// character at position 1,900 refuses the run exactly as one at position 0
/// does, so batching can never type a prefix and then discover the problem.
/// What the batches buy is pacing, not a weaker rule.
pub fn text_to_plan(text: &str) -> Result<TextPlan, TextError> {
    use crate::message::{InputControlMessage, KeyAction, MOD_SHIFT};
    let total_chars = text.chars().count();
    let keys = plan_keystrokes(text)?
        .into_iter()
        .map(|(k, chars_through)| {
            let modifiers = if k.shift { MOD_SHIFT } else { 0 };
            TypedKey {
                down: InputControlMessage::KeyEvent {
                    scan_code: k.scan_code,
                    action: KeyAction::Down,
                    modifiers,
                },
                up: InputControlMessage::KeyEvent {
                    scan_code: k.scan_code,
                    action: KeyAction::Up,
                    modifiers,
                },
                chars_through,
            }
        })
        .collect();
    Ok(TextPlan { keys, total_chars })
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
    Ok(text_to_plan(text)?
        .keys
        .into_iter()
        .flat_map(|k| [k.down, k.up])
        .collect())
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

    /// A representative paragraph: several sentences, capitals, digits and the
    /// punctuation people actually write. Not anyone's real text.
    const PARAGRAPH: &str = "The quarterly backup finished at 02:14, three minutes later than \
the night before. Two of the forty-one folders were skipped because their owners had them open; \
both were picked up on the retry at 02:30. Disk usage on the archive volume is now 61% (up from \
58% last week), which leaves roughly five months at the current rate. Nothing needs doing today, \
but the oldest snapshots (those before 2024-03-01) could be pruned if space becomes tight. The \
restore test from Tuesday passed: every file matched its checksum, and the slowest one took 9.6 \
seconds. If anything looks wrong, check the log first - it names the folder, the time and the \
reason - and only then rerun the job by hand. Questions can go in the usual thread; please keep \
passwords and keys out of it, even partial ones. Thanks to everyone who kept their machines on \
overnight; it made the difference between a clean run and a half-finished one.";

    /// RD-TEXT-1. The operator's report: typing stops at about two sentences.
    /// The ceiling was 256 characters; a paragraph must go through in one run.
    #[test]
    fn a_paragraph_is_accepted_in_one_run() {
        let len = PARAGRAPH.chars().count();
        assert!(
            len > 256,
            "the fixture must be longer than the old ceiling, is {len}"
        );
        let strokes = text_to_keystrokes(PARAGRAPH).expect("a paragraph must be typable");
        assert_eq!(
            strokes.len(),
            len,
            "one keystroke per character, nothing dropped"
        );
        // The old ceiling plus one, which is where the refusal used to start.
        assert_eq!(
            text_to_keystrokes(&"a".repeat(257)).map(|s| s.len()),
            Ok(257)
        );
    }

    /// The new ceiling is exactly 2,000 characters.
    #[test]
    fn the_ceiling_is_two_thousand_characters() {
        assert_eq!(MAX_TEXT_CHARS, 2000);
        assert_eq!(
            text_to_keystrokes(&"a".repeat(2000)).map(|s| s.len()),
            Ok(2000)
        );
        assert_eq!(
            text_to_keystrokes(&"a".repeat(2001)),
            Err(TextError::TooLong {
                len: 2001,
                max: 2000
            })
        );
    }

    fn batch_events(batch: &[TypedKey]) -> usize {
        batch.iter().map(kernel_events).sum()
    }

    /// The cost model is `inject_linux`'s emission: a frame per modifier and
    /// one for the key, each with its `SYN_REPORT`, for press and release.
    #[test]
    fn a_plain_key_is_four_kernel_events_and_a_shifted_one_eight() {
        let plan = text_to_plan("aA").unwrap();
        assert_eq!(kernel_events(&plan.keys[0]), 4);
        assert_eq!(kernel_events(&plan.keys[1]), 8);
    }

    /// Batching is pacing only: laid end to end, the batches are exactly the
    /// sequence the unbatched expansion produces — same keys, same order,
    /// every press followed by its own release.
    #[test]
    fn batches_flatten_to_exactly_the_unbatched_sequence() {
        let plan = text_to_plan(PARAGRAPH).unwrap();
        let flat: Vec<_> = plan
            .batches()
            .into_iter()
            .flat_map(|b| b.iter().flat_map(|k| [k.down.clone(), k.up.clone()]))
            .collect();
        assert_eq!(flat, text_to_messages(PARAGRAPH).unwrap());
        assert!(
            plan.batches().len() > 1,
            "a paragraph must take more than one batch"
        );
    }

    /// Greedy: every batch but the last is full — the next keystroke would not
    /// have fitted. A batch smaller than it needs to be is pacing for nothing.
    #[test]
    fn batches_are_cut_greedily_by_event_cost() {
        let plan = text_to_plan(PARAGRAPH).unwrap();
        let batches = plan.batches();
        let mut next = 0;
        for (i, b) in batches.iter().enumerate() {
            next += b.len();
            assert!(
                batch_events(b) <= TEXT_BATCH_EVENTS,
                "batch {i} is {} events",
                batch_events(b)
            );
            if i + 1 < batches.len() {
                assert!(
                    batch_events(b) + kernel_events(&plan.keys[next]) > TEXT_BATCH_EVENTS,
                    "batch {i} stopped while the next keystroke still fitted"
                );
            }
        }
        assert_eq!(
            next,
            plan.keys.len(),
            "every keystroke in exactly one batch"
        );
    }

    /// The reason for twenty: THREE batches must fit the reader's buffer, so a
    /// compositor that misses two pauses in a row still loses nothing. Worst
    /// case is every character shifted.
    #[test]
    fn three_batches_fit_the_evdev_buffer() {
        for text in [
            PARAGRAPH.to_string(),
            "A".repeat(MAX_TEXT_CHARS),
            "a".repeat(MAX_TEXT_CHARS),
        ] {
            let plan = text_to_plan(&text).unwrap();
            let batches = plan.batches();
            for w in batches.windows(3) {
                let waiting: usize = w.iter().map(|b| batch_events(b)).sum();
                assert!(
                    waiting < EVDEV_READER_BUFFER_EVENTS,
                    "three batches are {waiting} events; the reader holds {}",
                    EVDEV_READER_BUFFER_EVENTS - 1
                );
            }
        }
        // The arithmetic the doc comment states, so a change to either
        // constant has to be argued again.
        assert!(3 * TEXT_BATCH_EVENTS < EVDEV_READER_BUFFER_EVENTS);
        assert!(
            4 * 16 >= EVDEV_READER_BUFFER_EVENTS,
            "a fourth batch must be able to overflow"
        );
    }

    /// A batch never holds less than one keystroke, even if a single key's
    /// events exceeded the budget — otherwise the cut would loop forever.
    #[test]
    fn a_batch_always_makes_progress() {
        let plan = text_to_plan(&"A".repeat(50)).unwrap();
        assert!(plan.batches().iter().all(|b| !b.is_empty()));
    }

    /// `chars_through` counts the SOURCE text, `\r` included, so a run that
    /// stops part-way can say where it stopped in what the operator wrote.
    #[test]
    fn chars_through_counts_the_source_text_including_skipped_returns() {
        let plan = text_to_plan("ab\r\ncd\r").unwrap();
        let through: Vec<usize> = plan.keys.iter().map(|k| k.chars_through).collect();
        assert_eq!(through, vec![1, 2, 4, 5, 6]);
        assert_eq!(
            plan.total_chars, 7,
            "the trailing CR is consumed by a finished run"
        );
    }

    /// Go appends one Enter; the run must type exactly that one, last. Type
    /// appends none, and the run must type none.
    #[test]
    fn a_submitted_paragraph_ends_with_exactly_one_enter() {
        const ENTER: u16 = 0x1C;
        let is_enter = |k: &TypedKey| {
            matches!(
                k.down,
                crate::message::InputControlMessage::KeyEvent {
                    scan_code: ENTER,
                    ..
                }
            )
        };
        let submitted = text_to_plan(&format!("{PARAGRAPH}\n")).unwrap();
        assert_eq!(submitted.keys.iter().filter(|k| is_enter(k)).count(), 1);
        assert!(
            is_enter(submitted.keys.last().unwrap()),
            "the Enter must be the final keystroke"
        );

        let staged = text_to_plan(PARAGRAPH).unwrap();
        assert_eq!(staged.keys.iter().filter(|k| is_enter(k)).count(), 0);
    }

    /// All or nothing survives batching: a bad character near the END of a
    /// long run refuses the whole run before a single batch exists.
    #[test]
    fn a_late_bad_character_refuses_the_whole_plan() {
        let text = format!("{}\u{e9}{}", "a".repeat(1900), "b".repeat(50));
        assert_eq!(
            text_to_plan(&text),
            Err(TextError::Unsupported {
                ch: '\u{e9}',
                at: 1900
            })
        );
    }

    #[test]
    fn an_empty_run_has_no_batches() {
        let plan = text_to_plan("").unwrap();
        assert_eq!(plan.batches().len(), 0);
        assert_eq!(plan.total_chars, 0);
    }

    /// The ceiling is in characters on the new limit too: 2,001 three-byte
    /// characters are refused for LENGTH (checked before content), 2,000 for
    /// content.
    #[test]
    fn the_paragraph_ceiling_counts_characters_not_bytes() {
        assert_eq!(
            text_to_plan(&"\u{20AC}".repeat(MAX_TEXT_CHARS + 1)),
            Err(TextError::TooLong {
                len: MAX_TEXT_CHARS + 1,
                max: MAX_TEXT_CHARS
            })
        );
        assert_eq!(
            text_to_plan(&"\u{20AC}".repeat(MAX_TEXT_CHARS)),
            Err(TextError::Unsupported {
                ch: '\u{20AC}',
                at: 0
            })
        );
        // An astral character is one character, not two UTF-16 units.
        assert!(matches!(
            text_to_plan(&"\u{1F600}".repeat(MAX_TEXT_CHARS)),
            Err(TextError::Unsupported { .. })
        ));
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
