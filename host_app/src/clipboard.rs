//! The host's clipboard, as far as a paired phone may reach it.
//!
//! # Why this exists, and why it was absent
//!
//! Plan §4.2 cut clipboard sync from v1 as a convenience that "adds
//! permissions, parsers, filesystem risk, or misleading dormant surfaces
//! **before view/control works end to end**". View and control now work end to
//! end and are proven on hardware, so the stated precondition is met — the cut
//! was sequencing, not a prohibition.
//!
//! What was there before was worse than nothing: a `clipboard_sync` handler
//! that acknowledged the command **without ever touching a clipboard**, and an
//! Android button that sent the phone's clipboard into it. Block 10 was right
//! to find that; it then deleted the operator's buttons without asking. This is
//! the feature those buttons always claimed to be.
//!
//! # What is deliberately not here
//!
//! Images, files, and any automatic background sync. A clipboard that mirrors
//! itself continuously is a channel that moves a password off a machine because
//! it happened to be copied, with nobody having asked for it. **Every transfer
//! here is one the operator pressed a button for.**
//!
//! # Text never reaches a log
//!
//! Nothing in this module prints clipboard content, and neither does its
//! caller. Errors name the failure, never the payload. That is a rule, not an
//! accident: a clipboard is where passwords are, and a redacted log is the only
//! kind worth having.

// Only the Linux path pipes into a child process.
#[cfg(target_os = "linux")]
use std::io::Write;

/// A first, cheap ceiling on clipboard text in UTF-8 bytes.
///
/// Not the real limit — [`validate`] also checks what the text costs **once
/// encoded**, which is the number the envelope actually has to carry. This one
/// exists so an absurd payload is refused before anything tries to escape it.
///
/// **Refused, never truncated.** Half a password is not a password and half a
/// command is a different command; silently shortening either is how a clipboard
/// feature becomes a way to run something nobody typed.
pub const MAX_TEXT_BYTES: usize = 8192;

/// Room left for the rest of `{"type":"clipboard","text":…}` around the text.
const ENVELOPE_OVERHEAD: usize = 64;

/// Why a clipboard operation could not be performed.
///
/// Each variant is a distinct thing the operator can do something about, and
/// none of them carries clipboard content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    /// The payload was larger than [`MAX_TEXT_BYTES`].
    TooLarge { bytes: usize },
    /// The text contained a NUL, which cannot survive the tools that carry it.
    EmbeddedNul,
    /// This platform has no clipboard implementation in this build.
    ///
    /// Constructed only off Linux, so a Linux release build sees it as dead.
    /// Allowed there specifically: the variant must stay reachable on the
    /// platforms that return it, and a blanket allow would hide it going dead
    /// on those too.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Unsupported,
    /// The platform's clipboard tool is not installed or would not run.
    ///
    /// Constructed only where there is a tool to run, so a Windows build sees
    /// it as dead. Allowed there specifically rather than blanket-allowed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ToolUnavailable,
    /// The tool ran and failed. See [`ToolUnavailable`](Self::ToolUnavailable).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ToolFailed,
    /// The host's clipboard holds something, but not text — an image, a file.
    ///
    /// Distinct from empty ON PURPOSE. "Nothing is copied" and "what is copied
    /// is a screenshot" want different things from the operator, and both used
    /// to arrive as an empty string.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NotText,
}

impl ClipboardError {
    /// A short reason for the wire. Names the failure; never the payload.
    pub fn reason(&self) -> &'static str {
        match self {
            ClipboardError::TooLarge { .. } => "clipboard text too large",
            ClipboardError::EmbeddedNul => "clipboard text contains a NUL",
            ClipboardError::Unsupported => "no clipboard support on this host platform",
            ClipboardError::ToolUnavailable => "host clipboard tool unavailable",
            ClipboardError::ToolFailed => "host clipboard tool failed",
            ClipboardError::NotText => "the host's clipboard is not text",
        }
    }
}

/// Check a payload before it goes anywhere near the platform.
///
/// Pure, so the rules are tested without a compositor. A NUL is refused rather
/// than stripped: the value that came out the other end would not be the value
/// that went in, and a caller pasting it would not know.
///
/// **The size that matters is the ENCODED size.** A raw byte cap is the wrong
/// instrument on its own: JSON escaping inflates, and a control character costs
/// six characters rather than one. A cap chosen small enough to survive the
/// worst case would refuse ordinary text at a fraction of what the envelope can
/// hold; a cap chosen for ordinary text would overflow it on the pathological
/// case. So the raw cap is a cheap first refusal and the encoded length is
/// measured against the envelope that has to carry it.
///
/// The first version of this asserted `MAX_TEXT_BYTES * 6 < max_payload` and
/// its own test caught that 4096 did not fit. That arithmetic was the right
/// question asked about the wrong quantity.
pub fn validate(text: &str) -> Result<(), ClipboardError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(ClipboardError::TooLarge { bytes: text.len() });
    }
    if text.as_bytes().contains(&0) {
        return Err(ClipboardError::EmbeddedNul);
    }
    let encoded = encoded_len(text);
    if encoded + ENVELOPE_OVERHEAD > wire::Kind::ControlJson.max_payload() {
        return Err(ClipboardError::TooLarge { bytes: encoded });
    }
    Ok(())
}

/// What this text costs as a JSON string, escaping included.
///
/// Measured with the same serializer that will do the encoding rather than
/// estimated. An estimate that is ever wrong in the generous direction is a
/// message the peer refuses after we told the operator it was sent.
fn encoded_len(text: &str) -> usize {
    serde_json::Value::String(text.to_string())
        .to_string()
        .len()
}

/// Put text on the host's clipboard.
#[cfg(target_os = "linux")]
pub fn write_host_clipboard(text: &str) -> Result<(), ClipboardError> {
    validate(text)?;
    // **Through stdin, never argv.** A command line is world-readable in
    // /proc/<pid>/cmdline, so passing clipboard text as an argument would
    // publish it to every process on the machine for as long as wl-copy lived.
    // That is the opposite of what this feature is for.
    let mut child = std::process::Command::new("wl-copy")
        .arg("--type")
        .arg("text/plain;charset=utf-8")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| ClipboardError::ToolUnavailable)?;
    child
        .stdin
        .take()
        .ok_or(ClipboardError::ToolFailed)?
        .write_all(text.as_bytes())
        .map_err(|_| ClipboardError::ToolFailed)?;
    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        _ => Err(ClipboardError::ToolFailed),
    }
}

/// Read the host's clipboard.
#[cfg(target_os = "linux")]
pub fn read_host_clipboard() -> Result<String, ClipboardError> {
    let out = std::process::Command::new("wl-paste")
        // Force a stable locale: the empty case is told apart by wl-paste's own
        // message, and a translated one would read as an unknown failure.
        // Failing closed there is right, but failing closed on every read in a
        // non-English session would be a feature that quietly does not work.
        .env("LC_ALL", "C")
        .arg("--no-newline")
        .arg("--type")
        .arg("text/plain;charset=utf-8")
        .output()
        .map_err(|_| ClipboardError::ToolUnavailable)?;

    if out.status.success() {
        let text = String::from_utf8(out.stdout).map_err(|_| ClipboardError::ToolFailed)?;
        validate(&text)?;
        return Ok(text);
    }

    // ── Everything below is a NON-ZERO exit, and they are not the same thing ──
    //
    // This used to be one line: `if !out.status.success() { return Ok(String::new()) }`.
    // That turned EVERY failure into "the clipboard is empty" — a dead
    // compositor, a clipboard holding an image, and nothing copied at all all
    // arrived as the same empty string. It matters because the client is
    // allowed to overwrite the phone's clipboard with an empty result: under
    // the old code a FAILURE could silently wipe what the operator had copied
    // on their phone, which is the one outcome this feature must never produce.
    //
    // wl-paste exits 1 for all of them, so the exit code cannot tell them
    // apart; its message can. Matching on that text is not lovely, and the
    // structural alternative (`--list-types`) is exit-code-ambiguous in exactly
    // the same way, so it would move the guesswork rather than remove it.
    //
    // UNKNOWN STDERR IS A FAILURE, NOT AN EMPTY CLIPBOARD. Fail closed: the
    // phone keeps what it has.
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if stderr.contains("nothing is copied") {
        Ok(String::new())
    } else if stderr.contains("not available as requested type") {
        Err(ClipboardError::NotText)
    } else {
        Err(ClipboardError::ToolFailed)
    }
}

/// Windows and everything else: declared, not silently pretended.
///
/// A stub that returned `Ok(())` here would be exactly the defect this module
/// replaces — `clipboard_sync` acknowledging a transfer it never performed. The
/// refusal names the platform so the operator can see it is a gap rather than a
/// fault.
#[cfg(not(target_os = "linux"))]
pub fn write_host_clipboard(text: &str) -> Result<(), ClipboardError> {
    validate(text)?;
    Err(ClipboardError::Unsupported)
}

/// See [`write_host_clipboard`].
#[cfg(not(target_os = "linux"))]
pub fn read_host_clipboard() -> Result<String, ClipboardError> {
    Err(ClipboardError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_accepted() {
        assert_eq!(validate("hello"), Ok(()));
        assert_eq!(validate(""), Ok(()));
        assert_eq!(validate("héllo — ünïcode ✓"), Ok(()));
    }

    #[test]
    fn the_limit_is_on_bytes_not_characters() {
        // A multi-byte character must count for what it costs on the wire, or a
        // limit expressed in characters lets four times the bytes through.
        let wide = "é".repeat(MAX_TEXT_BYTES); // two bytes each
        assert!(matches!(
            validate(&wide),
            Err(ClipboardError::TooLarge { .. })
        ));
        assert_eq!(validate(&"a".repeat(MAX_TEXT_BYTES)), Ok(()));
        assert!(matches!(
            validate(&"a".repeat(MAX_TEXT_BYTES + 1)),
            Err(ClipboardError::TooLarge { .. })
        ));
    }

    /// Text that fits raw but not once escaped.
    ///
    /// A control character with no short form costs six as `\u0001`, so a
    /// payload well inside the byte cap is still too big for the envelope. This
    /// is the case a raw cap alone cannot see.
    ///
    /// Tab was the first choice here and was WRONG: `serde_json` writes it as
    /// `\t`, two characters, so 4000 tabs fit comfortably and the test failed
    /// for a reason that had nothing to do with the rule. Which characters are
    /// expensive is a property of the encoder, not an intuition — which is why
    /// `encoded_len` asks the encoder rather than estimating.
    #[test]
    fn text_that_only_overflows_once_escaped_is_refused() {
        let controls = "\u{01}".repeat(4000);
        assert!(
            controls.len() <= MAX_TEXT_BYTES,
            "the raw cap must not be what catches this"
        );
        assert!(matches!(
            validate(&controls),
            Err(ClipboardError::TooLarge { .. })
        ));
    }

    /// Ordinary text gets the room the envelope really has, rather than a
    /// worst-case fraction of it.
    #[test]
    fn ordinary_text_gets_the_full_envelope() {
        assert_eq!(validate(&"a".repeat(8000)), Ok(()));
    }

    /// Refused, not truncated. Half a password is not a password and half a
    /// command is a different command.
    #[test]
    fn an_oversized_payload_is_refused_whole() {
        let err = validate(&"a".repeat(MAX_TEXT_BYTES + 1)).unwrap_err();
        assert_eq!(
            err,
            ClipboardError::TooLarge {
                bytes: MAX_TEXT_BYTES + 1
            }
        );
        assert_eq!(err.reason(), "clipboard text too large");
    }

    /// A NUL cannot survive the tools that carry the text, so accepting it
    /// would deliver something other than what was sent — and the caller
    /// pasting it would have no way to know.
    #[test]
    fn a_nul_is_refused_rather_than_stripped() {
        assert_eq!(validate("before\0after"), Err(ClipboardError::EmbeddedNul));
    }

    /// Every reason is short, distinct, and free of anything that could be
    /// clipboard content. These strings go on the wire and into the log.
    #[test]
    fn no_reason_can_leak_a_payload() {
        let reasons = [
            ClipboardError::TooLarge { bytes: 99999 }.reason(),
            ClipboardError::EmbeddedNul.reason(),
            ClipboardError::Unsupported.reason(),
            ClipboardError::ToolUnavailable.reason(),
            ClipboardError::ToolFailed.reason(),
            ClipboardError::NotText.reason(),
        ];
        for r in reasons {
            assert!(!r.is_empty());
            assert!(r.is_ascii(), "a reason must not carry arbitrary text");
        }
        let unique: std::collections::HashSet<_> = reasons.iter().collect();
        assert_eq!(unique.len(), reasons.len(), "two failures read the same");
    }

    /// Whatever `validate` accepts must fit the envelope that carries it.
    ///
    /// Asserted over the shapes that stress the encoder rather than by
    /// arithmetic on the cap: the arithmetic version of this test is what
    /// caught the first bound being wrong, and replacing it with a claim about
    /// accepted values is the stronger form of the same question.
    #[test]
    fn nothing_accepted_can_overflow_a_control_envelope() {
        for text in [
            "a".repeat(MAX_TEXT_BYTES),
            "é".repeat(MAX_TEXT_BYTES / 2),
            "\u{01}".repeat(MAX_TEXT_BYTES / 2),
            "\"\\".repeat(MAX_TEXT_BYTES / 2),
            "✓".repeat(MAX_TEXT_BYTES / 3),
        ] {
            if validate(&text).is_ok() {
                let msg = serde_json::json!({ "type": "clipboard", "text": text }).to_string();
                assert!(
                    msg.len() <= wire::Kind::ControlJson.max_payload(),
                    "an accepted payload encoded to {} bytes, past the envelope",
                    msg.len()
                );
            }
        }
    }

    /// **There is one system clipboard, and cargo runs tests in parallel.**
    ///
    /// Both live tests below manipulate it, and without this they interleave:
    /// one clears the clipboard while the other is reading back what it just
    /// wrote. Both failed on their first run together, and neither failure had
    /// anything to do with the code under test — the round trip had passed
    /// alone minutes earlier.
    ///
    /// The same shape as `main.rs`'s `ENV_LOCK`, for the same reason: a global
    /// the tests share is a global the tests must take turns with.
    static CLIPBOARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Puts the operator's clipboard back however the live test ends.
    struct Restore(Option<String>);

    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                // Best effort, and deliberately silent about the content.
                let _ = write_host_clipboard(&previous);
            }
        }
    }

    /// The three non-zero exits, told apart on real tools.
    ///
    /// This is the test that would have caught the defect it exists for. Every
    /// one of these cases used to return `Ok("")` — an empty clipboard, a
    /// clipboard holding a non-text type, and a genuine failure were one value.
    /// The client is allowed to overwrite the phone's clipboard with an empty
    /// result, so the old behaviour let a FAILURE wipe what the operator had
    /// copied on their phone.
    ///
    /// Hardware-gated for the same reason as the round trip, and it restores
    /// the operator's clipboard the same way.
    #[test]
    fn live_an_empty_clipboard_is_told_apart_from_a_failure() {
        if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
            eprintln!("skipping: set RD_USE_HW=1 with a live Wayland session to run this");
            return;
        }
        let _serial = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let previous = read_host_clipboard().ok();
        let _restore = Restore(previous);

        // 1. Genuinely empty. wl-paste says "Nothing is copied".
        let cleared = std::process::Command::new("wl-copy")
            .arg("--clear")
            .status()
            .expect("wl-copy --clear could not run");
        assert!(cleared.success());
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            read_host_clipboard(),
            Ok(String::new()),
            "an empty clipboard must read as empty, not as a failure"
        );

        // 2. Holding something that is NOT text. The operator needs to be told
        //    that rather than shown an empty result, because the two want
        //    different things from them.
        let mut child = std::process::Command::new("wl-copy")
            .arg("--type")
            .arg("image/png")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("wl-copy could not run");
        std::io::Write::write_all(
            &mut child.stdin.take().unwrap(),
            // Not a real PNG; wl-copy does not care what the bytes are, only
            // what type they are offered as, which is the whole point here.
            b"\x89PNG\r\n\x1a\n not really a png",
        )
        .unwrap();
        child.wait().expect("wl-copy did not finish");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            read_host_clipboard(),
            Err(ClipboardError::NotText),
            "a clipboard holding an image must NOT read as empty"
        );

        // 3. And text still works, so the branch above did not swallow it.
        write_host_clipboard("back to text").expect("wl-copy could not set text");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(read_host_clipboard(), Ok("back to text".to_string()));
    }

    /// Hardware-gated proof that the host's clipboard is really reachable.
    ///
    /// Runs only when `RD_USE_HW=1`, because it needs a live Wayland session
    /// and the `wl-clipboard` tools. Everything decidable without a desktop —
    /// the bounds, the escaping arithmetic, the refusals — is above. What is
    /// not decidable there is whether `wl-copy` and `wl-paste` actually carry
    /// text on this machine, and a feature whose whole job is moving text
    /// deserves one test that moves text.
    ///
    /// **The operator's clipboard is saved and put back**, by a guard that runs
    /// even if the assertions fail. A test that ran on someone's desktop and
    /// silently discarded what they had copied would be a small theft of their
    /// work.
    #[test]
    fn live_host_clipboard_round_trips_real_text() {
        if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
            eprintln!("skipping: set RD_USE_HW=1 with a live Wayland session to run this");
            return;
        }
        let _serial = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Saved BEFORE anything is written; restored by the guard's Drop.
        let previous = read_host_clipboard().ok();
        let _restore = Restore(previous);

        // Distinctive enough that a stale clipboard cannot pass for a fresh
        // write, which is how a round-trip test fools itself.
        let marker = format!(
            "RemoteDexter clipboard proof {} \u{2713} héllo",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        write_host_clipboard(&marker).expect("wl-copy could not set the clipboard");
        let read_back = read_host_clipboard().expect("wl-paste could not read it back");

        assert_eq!(
            read_back, marker,
            "what came out of the host clipboard is not what went in"
        );
        // Non-ASCII survives. The tools are asked for text/plain;charset=utf-8
        // precisely so this holds, and a clipboard that mangles accented text
        // is one an operator cannot trust with a password.
        assert!(
            read_back.contains('\u{2713}'),
            "a non-ASCII character was lost"
        );
        assert!(read_back.contains("héllo"), "accented text was mangled");
    }
}
