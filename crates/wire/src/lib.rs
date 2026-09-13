//! One versioned envelope for everything that crosses the encrypted link.
//!
//! # What this replaces, and why
//!
//! The old `multiplexer::Frame` treated its length field as a *minimum*: it
//! checked that at least `5 + payload_len` bytes were present and never that
//! there were exactly that many. Trailing bytes parsed clean and were silently
//! discarded, so two different byte strings decoded to the same frame. A parser
//! that ignores what it does not understand cannot detect a desync, and it lets
//! one peer append bytes that this side drops and another implementation might
//! not — which is how two ends come to disagree about what was said. That
//! defect is recorded as a failing test in `modules/multiplexer`
//! (`red_block10_trailing_bytes_are_accepted_today`).
//!
//! Here, **length is the exact extent**. Short is `Truncated`, long is
//! `TrailingBytes`, and both are refusals.
//!
//! # The envelope
//!
//! ```text
//! [0]     version : u8    must be WIRE_VERSION
//! [1]     kind    : u8    one of Kind
//! [2..4]  flags   : u16   big-endian, reserved; unknown bits are preserved
//! [4..8]  length  : u32   big-endian, EXACT payload length
//! [8..]   payload
//! ```
//!
//! Eight bytes, fixed. No optional fields and no extension point: the plan is
//! explicit that a generic extensible channel API waits until two real features
//! need independent flow control, and an unused extension mechanism is a
//! liability that has to be parsed by everyone forever.
//!
//! # Where it sits
//!
//! **Every envelope is inside Noise.** That is why the primitive is
//! [`decode_exact`] over one complete buffer rather than a streaming decoder:
//! the transport already delivers exactly one plaintext per message, so a
//! decoder that tolerated partial input would be inventing a framing problem
//! that does not exist and losing the strictness in the process.
//!
//! # Flags
//!
//! Reserved and carried through untouched. They are deliberately NOT validated
//! against a known set: a receiver that refuses unknown flag bits cannot be
//! given a backwards-compatible hint later, and the version byte already exists
//! for changes that actually alter meaning.

/// The only version this build speaks.
pub const WIRE_VERSION: u8 = 1;

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 8;

/// The largest plaintext a Noise message carries here.
///
/// Mirrors `MAX_NOISE_FRAME` in the client transport. An envelope that could
/// not fit inside one Noise message would be undeliverable by construction,
/// which the compile-time assertion below rules out.
pub const MAX_NOISE_PLAINTEXT: usize = 65535;

/// Deepest nesting accepted in control JSON.
///
/// Bounded because depth is what turns a small message into unbounded work: a
/// few hundred bytes of `[[[[...` is cheap to send and expensive to parse
/// recursively. 32 is far past anything the protocol actually sends (the
/// deepest real command nests three levels) while leaving no room to argue.
pub const MAX_CONTROL_JSON_DEPTH: usize = 32;

/// What an envelope carries.
///
/// Five kinds, closed. Clipboard and file transfer are absent on purpose —
/// they are cut from v1, and a kind reserved for a feature that does not exist
/// is a parser branch nobody tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A control/response command as JSON. Depth- and size-bounded.
    ControlJson,
    /// One input event in the pinned `android_input_wire_v1` JSON form.
    InputV1,
    /// One chunk of an encoded video frame, `stream_chunk` format.
    FrameChunkV1,
    /// Liveness. Carries nothing.
    Ping,
    /// Orderly teardown. Carries a short redacted reason.
    Close,
}

impl Kind {
    /// Wire code. Zero is not used, so an all-zero buffer cannot decode.
    pub const fn code(self) -> u8 {
        match self {
            Kind::ControlJson => 1,
            Kind::InputV1 => 2,
            Kind::FrameChunkV1 => 3,
            Kind::Ping => 4,
            Kind::Close => 5,
        }
    }

    /// Wire code to kind, or `None` for anything unrecognised.
    pub const fn from_code(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::ControlJson),
            2 => Some(Kind::InputV1),
            3 => Some(Kind::FrameChunkV1),
            4 => Some(Kind::Ping),
            5 => Some(Kind::Close),
            _ => None,
        }
    }

    /// Largest payload this kind may carry.
    ///
    /// Per kind rather than one global ceiling, because the ceiling is what
    /// bounds the damage: a control message has no business being 60 kB, and
    /// giving it the frame-chunk allowance would let a peer spend the whole
    /// budget on the one path that runs a parser.
    pub const fn max_payload(self) -> usize {
        match self {
            // Comfortably past the largest real command; small enough that a
            // depth-bounded scan is trivial work.
            Kind::ControlJson => 16 * 1024,
            // Input events are tens of bytes. This is pure headroom.
            Kind::InputV1 => 4 * 1024,
            // host_app's STREAM_CHUNK_PAYLOAD (60000) plus stream_chunk's
            // 14-byte header. Anchored by a test below.
            Kind::FrameChunkV1 => 60_014,
            Kind::Ping => 0,
            // A reason code and nothing an attacker chose the length of.
            Kind::Close => 64,
        }
    }

    /// Whether this kind must carry an empty payload.
    pub const fn must_be_empty(self) -> bool {
        matches!(self, Kind::Ping)
    }

    /// Whether this kind must carry a non-empty payload.
    ///
    /// A zero-length `ControlJson` is not an empty command, it is a malformed
    /// one: there is no JSON document of zero bytes. Accepting it would push
    /// the refusal down into whatever tried to interpret it.
    pub const fn must_not_be_empty(self) -> bool {
        matches!(
            self,
            Kind::ControlJson | Kind::InputV1 | Kind::FrameChunkV1 | Kind::Close
        )
    }
}

/// An envelope must fit inside one Noise message, or it can never be sent.
const _: () = assert!(HEADER_LEN + Kind::FrameChunkV1.max_payload() <= MAX_NOISE_PLAINTEXT);
const _: () = assert!(HEADER_LEN + Kind::ControlJson.max_payload() <= MAX_NOISE_PLAINTEXT);

/// Why a buffer was refused.
///
/// Carries detail for the local log. It is deliberately NOT what goes on the
/// wire — see [`WireError::redacted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Fewer than [`HEADER_LEN`] bytes.
    ShortHeader { got: usize },
    /// Version byte this build does not speak.
    UnknownVersion { got: u8 },
    /// Kind byte outside [`Kind`].
    UnknownKind { got: u8 },
    /// Declared length exceeds the kind's ceiling.
    TooLong {
        kind: Kind,
        declared: usize,
        max: usize,
    },
    /// Fewer payload bytes than declared.
    Truncated { declared: usize, available: usize },
    /// More bytes than declared. The defect this crate exists to fix.
    TrailingBytes { extra: usize },
    /// A kind that carries nothing was given a payload.
    MustBeEmpty { kind: Kind },
    /// A kind that must carry something was given nothing.
    MustNotBeEmpty { kind: Kind },
    /// Control JSON nested past [`MAX_CONTROL_JSON_DEPTH`].
    ControlJsonTooDeep,
    /// Control JSON that is not a well-formed, balanced object.
    ControlJsonMalformed,
}

impl WireError {
    /// What may be told to the peer.
    ///
    /// Coarse on purpose. The detailed variant says how many bytes were
    /// trailing or what length was declared, and handing that back turns a
    /// refusal into a measuring instrument — a peer could probe the exact
    /// ceilings and the exact parse position where a buffer stopped being
    /// acceptable. The peer learns that it was refused and roughly which
    /// contract it broke; the operator's log keeps the rest.
    pub const fn redacted(&self) -> &'static str {
        match self {
            WireError::ShortHeader { .. }
            | WireError::Truncated { .. }
            | WireError::TrailingBytes { .. }
            | WireError::MustBeEmpty { .. }
            | WireError::MustNotBeEmpty { .. }
            | WireError::TooLong { .. } => "protocol error: malformed envelope",
            WireError::UnknownVersion { .. } => "protocol error: unsupported version",
            WireError::UnknownKind { .. } => "protocol error: unsupported message",
            WireError::ControlJsonTooDeep | WireError::ControlJsonMalformed => {
                "protocol error: malformed control message"
            }
        }
    }
}

/// One decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Build an envelope, enforcing the same rules the decoder does.
    ///
    /// Returning `Result` rather than allowing an invalid one to be constructed
    /// means a sender cannot emit something its own receiver would refuse —
    /// which is otherwise only discovered on the far side, as a dropped
    /// session with no local trace.
    pub fn new(kind: Kind, flags: u16, payload: Vec<u8>) -> Result<Self, WireError> {
        // The empty/non-empty rules come FIRST. A kind whose ceiling is zero
        // (Ping) would otherwise report every payload as `TooLong`, which is
        // true but useless: the contract broken is "this kind carries
        // nothing", and `MustBeEmpty` would be unreachable for the one kind it
        // describes. Both are refusals either way; this picks the accurate one.
        if !payload.is_empty() && kind.must_be_empty() {
            return Err(WireError::MustBeEmpty { kind });
        }
        if payload.is_empty() && kind.must_not_be_empty() {
            return Err(WireError::MustNotBeEmpty { kind });
        }
        if payload.len() > kind.max_payload() {
            return Err(WireError::TooLong {
                kind,
                declared: payload.len(),
                max: kind.max_payload(),
            });
        }
        if kind == Kind::ControlJson {
            validate_control_json(&payload)?;
        }
        Ok(Envelope {
            kind,
            flags,
            payload,
        })
    }

    /// Serialise. Exact by construction: the length written is the length sent.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(WIRE_VERSION);
        out.push(self.kind.code());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Decode exactly one envelope from exactly this buffer.
///
/// # Order of checks
///
/// Version, then kind, then the declared length against the kind's ceiling —
/// **before** the buffer is measured or anything is copied. A hostile header
/// declaring 4 GB is rejected on the ceiling, having touched eight bytes.
///
/// Note the stronger property that makes that safe: the declared length is
/// never used to size an allocation at all. The payload is copied from a slice
/// of the caller's buffer whose bounds have already been checked, so a length
/// field cannot reserve memory even transiently.
pub fn decode_exact(bytes: &[u8]) -> Result<Envelope, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::ShortHeader { got: bytes.len() });
    }
    let version = bytes[0];
    if version != WIRE_VERSION {
        return Err(WireError::UnknownVersion { got: version });
    }
    let Some(kind) = Kind::from_code(bytes[1]) else {
        return Err(WireError::UnknownKind { got: bytes[1] });
    };
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let declared = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

    // Same ordering as `Envelope::new`, and for the same reason. Both of these
    // read the declared length only to compare it with zero, so the property
    // that nothing is sized from an attacker's length still holds.
    if declared != 0 && kind.must_be_empty() {
        return Err(WireError::MustBeEmpty { kind });
    }
    if declared == 0 && kind.must_not_be_empty() {
        return Err(WireError::MustNotBeEmpty { kind });
    }
    if declared > kind.max_payload() {
        return Err(WireError::TooLong {
            kind,
            declared,
            max: kind.max_payload(),
        });
    }
    let available = bytes.len() - HEADER_LEN;
    if available < declared {
        return Err(WireError::Truncated {
            declared,
            available,
        });
    }
    if available > declared {
        return Err(WireError::TrailingBytes {
            extra: available - declared,
        });
    }

    let payload = bytes[HEADER_LEN..].to_vec();
    if kind == Kind::ControlJson {
        validate_control_json(&payload)?;
    }
    Ok(Envelope {
        kind,
        flags,
        payload,
    })
}

/// Bound control JSON before anything tries to interpret it.
///
/// A hand-written scanner, not a parser. It answers one question — is this a
/// balanced JSON object no deeper than [`MAX_CONTROL_JSON_DEPTH`] — without
/// building a tree, so the depth limit is enforced *before* the work it exists
/// to bound rather than after. It is intentionally not a full JSON validator:
/// whatever consumes the payload still parses it properly. This is a gate, and
/// a gate that duplicated the parser would be a second implementation to keep
/// in step.
pub fn validate_control_json(payload: &[u8]) -> Result<(), WireError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut seen_open = false;

    for &b in payload {
        if in_string {
            // An escaped quote does not end the string. Without this, a brace
            // inside "a\"{" would be counted as structure.
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                if !seen_open && b != b'{' {
                    // Top level must be an object: every command is
                    // `{"type": ...}`, and accepting a bare array here would
                    // hand the consumer something it has no branch for.
                    return Err(WireError::ControlJsonMalformed);
                }
                seen_open = true;
                depth += 1;
                if depth > MAX_CONTROL_JSON_DEPTH {
                    return Err(WireError::ControlJsonTooDeep);
                }
            }
            b'}' | b']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(WireError::ControlJsonMalformed)?;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => {
                if !seen_open {
                    return Err(WireError::ControlJsonMalformed);
                }
            }
        }
    }
    if in_string || depth != 0 || !seen_open {
        return Err(WireError::ControlJsonMalformed);
    }
    Ok(())
}

/// A close that can only happen once.
///
/// The multiplexer being replaced emitted CLOSE **twice** on every drained
/// channel — the same construct-and-send copy-pasted, comment and all, into one
/// match arm. A duplicate close is not cosmetic: the second one arrives after
/// the channel is already gone, so it is either an unsolicited frame for a
/// closed channel or a close for whatever reused the id.
///
/// [`CloseLatch::close`] returns `true` for exactly one caller, so "should I
/// send CLOSE" has one answer no matter how many paths ask.
#[derive(Debug, Default)]
pub struct CloseLatch {
    closed: std::sync::atomic::AtomicBool,
}

impl CloseLatch {
    pub const fn new() -> Self {
        CloseLatch {
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claim the close. `true` exactly once, for every caller and thread.
    pub fn close(&self) -> bool {
        !self.closed.swap(true, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(kind: Kind) -> Vec<u8> {
        match kind {
            Kind::ControlJson => br#"{"type":"ping"}"#.to_vec(),
            Kind::InputV1 => br#"{"type":"input_event","x":1}"#.to_vec(),
            Kind::FrameChunkV1 => vec![0x01, 0xAA, 0xBB],
            Kind::Ping => Vec::new(),
            Kind::Close => b"closing".to_vec(),
        }
    }

    const ALL: [Kind; 5] = [
        Kind::ControlJson,
        Kind::InputV1,
        Kind::FrameChunkV1,
        Kind::Ping,
        Kind::Close,
    ];

    /// Header + payload survive a round trip, for each kind in turn.
    fn round_trip(kind: Kind) {
        let sent = Envelope::new(kind, 0xBEEF, body(kind)).expect("valid envelope");
        let got = decode_exact(&sent.encode()).expect("must decode");
        assert_eq!(got, sent, "{kind:?} did not survive a round trip");
        assert_eq!(got.flags, 0xBEEF, "{kind:?} lost its flags");
    }

    #[test]
    fn round_trip_control_json() {
        round_trip(Kind::ControlJson);
    }

    #[test]
    fn round_trip_input_v1() {
        round_trip(Kind::InputV1);
    }

    #[test]
    fn round_trip_frame_chunk_v1() {
        round_trip(Kind::FrameChunkV1);
    }

    #[test]
    fn round_trip_ping() {
        round_trip(Kind::Ping);
    }

    #[test]
    fn round_trip_close() {
        round_trip(Kind::Close);
    }

    /// Ping is liveness. A payload on it is someone using it as a channel.
    #[test]
    fn ping_must_carry_no_payload() {
        assert_eq!(
            Envelope::new(Kind::Ping, 0, b"x".to_vec()),
            Err(WireError::MustBeEmpty { kind: Kind::Ping })
        );
        // And on the way in: a header claiming one byte for Ping.
        let mut raw = vec![WIRE_VERSION, Kind::Ping.code(), 0, 0, 0, 0, 0, 1];
        raw.push(b'x');
        assert_eq!(
            decode_exact(&raw),
            Err(WireError::MustBeEmpty { kind: Kind::Ping })
        );
    }

    /// There is no JSON document of zero bytes, and no chunk of no data.
    #[test]
    fn kinds_that_carry_data_refuse_an_empty_payload() {
        for kind in ALL.iter().copied().filter(|k| k.must_not_be_empty()) {
            assert_eq!(
                Envelope::new(kind, 0, Vec::new()),
                Err(WireError::MustNotBeEmpty { kind }),
                "{kind:?} accepted an empty payload"
            );
            let raw = vec![WIRE_VERSION, kind.code(), 0, 0, 0, 0, 0, 0];
            assert_eq!(
                decode_exact(&raw),
                Err(WireError::MustNotBeEmpty { kind }),
                "{kind:?} decoded from an empty payload"
            );
        }
    }

    /// The ceiling is inclusive. An off-by-one here silently costs a frame.
    #[test]
    fn every_kind_accepts_exactly_its_maximum() {
        for kind in ALL {
            let max = kind.max_payload();
            if max == 0 {
                continue; // Ping; covered by its own test.
            }
            let payload = if kind == Kind::ControlJson {
                let mut p = br#"{"k":""#.to_vec();
                p.resize(max - 2, b'a');
                p.extend_from_slice(br#""}"#);
                p
            } else {
                vec![b'z'; max]
            };
            assert_eq!(payload.len(), max);
            let env = Envelope::new(kind, 0, payload).unwrap_or_else(|e| {
                panic!("{kind:?} refused a payload of exactly its maximum {max}: {e:?}")
            });
            assert!(
                decode_exact(&env.encode()).is_ok(),
                "{kind:?} at max did not decode"
            );
        }
    }

    #[test]
    fn every_kind_refuses_one_byte_past_its_maximum() {
        for kind in ALL {
            let over = kind.max_payload() + 1;
            let expected = if kind.must_be_empty() {
                // A kind with a zero ceiling breaks the "carries nothing" rule
                // before it breaks any size rule, and that is the accurate
                // diagnosis. Refused either way.
                WireError::MustBeEmpty { kind }
            } else {
                WireError::TooLong {
                    kind,
                    declared: over,
                    max: kind.max_payload(),
                }
            };
            assert_eq!(
                Envelope::new(kind, 0, vec![b'z'; over]),
                Err(expected),
                "{kind:?} accepted one byte past its maximum"
            );
        }
    }

    /// A header may declare 4 GB. Nothing is measured or copied on that word.
    ///
    /// The buffer here is eight bytes — header only. If the decoder sized
    /// anything from the declared length, or indexed the payload before
    /// bounding it, this would abort rather than return.
    #[test]
    fn an_absurd_length_is_refused_before_anything_is_allocated() {
        let raw = vec![
            WIRE_VERSION,
            Kind::FrameChunkV1.code(),
            0,
            0,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];
        assert_eq!(
            decode_exact(&raw),
            Err(WireError::TooLong {
                kind: Kind::FrameChunkV1,
                declared: u32::MAX as usize,
                max: Kind::FrameChunkV1.max_payload(),
            })
        );
    }

    #[test]
    fn truncation_is_refused() {
        let env = Envelope::new(Kind::FrameChunkV1, 0, vec![1, 2, 3, 4, 5]).unwrap();
        let full = env.encode();
        for cut in 1..=5 {
            let short = &full[..full.len() - cut];
            assert_eq!(
                decode_exact(short),
                Err(WireError::Truncated {
                    declared: 5,
                    available: 5 - cut
                }),
                "a payload {cut} byte(s) short was accepted"
            );
        }
    }

    /// **The defect this crate exists for.**
    ///
    /// `multiplexer::Frame::from_bytes` accepts this — see
    /// `red_block10_trailing_bytes_are_accepted_today`. Length is the exact
    /// extent, so anything after it is a refusal, not padding to ignore.
    #[test]
    fn trailing_bytes_are_refused() {
        let env = Envelope::new(Kind::FrameChunkV1, 0, vec![1, 2, 3]).unwrap();
        let mut raw = env.encode();
        raw.extend_from_slice(b"TRAILING-GARBAGE");
        assert_eq!(
            decode_exact(&raw),
            Err(WireError::TrailingBytes { extra: 16 })
        );
    }

    #[test]
    fn unknown_version_is_refused() {
        let mut raw = Envelope::new(Kind::Ping, 0, Vec::new()).unwrap().encode();
        raw[0] = WIRE_VERSION.wrapping_add(1);
        assert_eq!(
            decode_exact(&raw),
            Err(WireError::UnknownVersion {
                got: WIRE_VERSION + 1
            })
        );
    }

    /// Zero is not a kind, so a zeroed buffer cannot decode into anything.
    #[test]
    fn unknown_kind_is_refused() {
        for code in [0u8, 6, 7, 200, 255] {
            let raw = vec![WIRE_VERSION, code, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                decode_exact(&raw),
                Err(WireError::UnknownKind { got: code }),
                "kind code {code} was accepted"
            );
        }
    }

    #[test]
    fn malformed_control_json_is_refused() {
        for bad in [
            &b"not json at all"[..],
            &b"{"[..], // unbalanced
            &b"}"[..], // closes nothing
            &br#"{"a":"unterminated"#[..],
            &br#"["top level array"]"#[..],
            &br#"{"a":1}}"#[..], // one close too many
        ] {
            assert!(
                Envelope::new(Kind::ControlJson, 0, bad.to_vec()).is_err(),
                "accepted malformed control JSON: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// A brace inside a string is data, not structure.
    #[test]
    fn braces_inside_strings_are_not_structure() {
        let ok = br#"{"reason":"a \"quoted\" { brace [ here"}"#.to_vec();
        assert!(
            Envelope::new(Kind::ControlJson, 0, ok).is_ok(),
            "a string containing braces was misread as nesting"
        );
    }

    /// Depth is bounded before the work it exists to bound.
    #[test]
    fn control_json_deeper_than_the_limit_is_refused() {
        let mut deep = br#"{"a":"#.to_vec();
        for _ in 0..MAX_CONTROL_JSON_DEPTH {
            deep.push(b'[');
        }
        for _ in 0..MAX_CONTROL_JSON_DEPTH {
            deep.push(b']');
        }
        deep.push(b'}');
        assert_eq!(
            validate_control_json(&deep),
            Err(WireError::ControlJsonTooDeep)
        );

        // One inside the limit still passes, so the bound is the stated one.
        let mut fine = br#"{"a":"#.to_vec();
        for _ in 0..(MAX_CONTROL_JSON_DEPTH - 2) {
            fine.push(b'[');
        }
        for _ in 0..(MAX_CONTROL_JSON_DEPTH - 2) {
            fine.push(b']');
        }
        fine.push(b'}');
        assert_eq!(validate_control_json(&fine), Ok(()));
    }

    /// Input is bounded by size and kind, and its JSON shape is the pinned
    /// `android_input_wire_v1` contract's business, not this crate's.
    ///
    /// Asserted so the boundary is deliberate rather than an omission: the
    /// contract file is checked by its own digest test on both sides, and a
    /// second opinion here would be a place for the two to disagree.
    #[test]
    fn input_payloads_are_bounded_but_not_reinterpreted() {
        let odd = Envelope::new(Kind::InputV1, 0, b"not json".to_vec());
        assert!(odd.is_ok(), "InputV1 shape is the contract's business");
        let too_big = Envelope::new(
            Kind::InputV1,
            0,
            vec![b'x'; Kind::InputV1.max_payload() + 1],
        );
        assert!(too_big.is_err(), "InputV1 must still be size-bounded");
    }

    /// The frame ceiling must match what the chunker actually emits.
    ///
    /// `host_app::STREAM_CHUNK_PAYLOAD` is 60000 and `stream_chunk::HEADER_LEN`
    /// is 14. If either moves without this ceiling moving, full-size chunks
    /// start being refused as `TooLong` — a black screen whose cause is two
    /// crates away. Written as an explicit statement of the sum rather than a
    /// dependency, keeping this crate dependency-free; the compile-time anchor
    /// against the real constants is added when host_app adopts the envelope.
    #[test]
    fn the_frame_chunk_ceiling_matches_the_chunker() {
        const HOST_STREAM_CHUNK_PAYLOAD: usize = 60_000;
        const STREAM_CHUNK_HEADER_LEN: usize = 14;
        assert_eq!(
            Kind::FrameChunkV1.max_payload(),
            HOST_STREAM_CHUNK_PAYLOAD + STREAM_CHUNK_HEADER_LEN,
            "the frame-chunk ceiling no longer matches the chunker's output"
        );
    }

    /// Decoding is stateless: kinds in any order decode independently.
    #[test]
    fn kinds_interleave_without_carrying_state() {
        let order = [
            Kind::FrameChunkV1,
            Kind::ControlJson,
            Kind::FrameChunkV1,
            Kind::InputV1,
            Kind::Ping,
            Kind::FrameChunkV1,
            Kind::Close,
        ];
        for kind in order {
            let sent = Envelope::new(kind, 0, body(kind)).expect("valid");
            let got = decode_exact(&sent.encode()).expect("must decode");
            assert_eq!(
                got.kind, kind,
                "decoding {kind:?} after another kind went wrong"
            );
            assert_eq!(got.payload, body(kind));
        }
    }

    /// One close, however many paths ask.
    #[test]
    fn close_latches_once_so_a_duplicate_close_cannot_be_sent() {
        let latch = CloseLatch::new();
        assert!(!latch.is_closed());
        assert!(latch.close(), "the first close must be the one that sends");
        assert!(latch.is_closed());
        for _ in 0..5 {
            assert!(!latch.close(), "a second close must NOT send another CLOSE");
        }
    }

    /// The latch holds under concurrency, which is where the old bug lived:
    /// the drainer's teardown ran on its own task.
    #[test]
    fn only_one_thread_can_claim_the_close() {
        use std::sync::Arc;
        let latch = Arc::new(CloseLatch::new());
        let winners: Arc<std::sync::atomic::AtomicUsize> =
            Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let l = Arc::clone(&latch);
            let w = Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                if l.close() {
                    w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            winners.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one caller may claim the close"
        );
    }

    /// A refusal must not become a measuring instrument.
    #[test]
    fn refusals_are_redacted_before_they_reach_the_peer() {
        let detailed = WireError::TooLong {
            kind: Kind::ControlJson,
            declared: 999_999,
            max: 16 * 1024,
        };
        let public = detailed.redacted();
        assert!(!public.contains("999999"), "the declared length leaked");
        assert!(!public.contains("16384"), "the ceiling leaked");
        assert_eq!(public, "protocol error: malformed envelope");
        assert!(
            !WireError::TrailingBytes { extra: 4096 }
                .redacted()
                .contains("4096"),
            "the trailing-byte count leaked"
        );
    }

    /// Arbitrary bytes must be refused, never panic.
    ///
    /// A deterministic sweep rather than a fuzzer: every kind code against a
    /// spread of lengths and truncations, plus the seeds that mattered while
    /// building this. `decode_exact` runs on attacker-controlled input, so
    /// "returns Err" and "does not abort the host" are the same requirement.
    #[test]
    fn arbitrary_bytes_are_refused_without_panicking() {
        let mut checked = 0usize;
        for version in [0u8, WIRE_VERSION, 2, 255] {
            for kind in [0u8, 1, 2, 3, 4, 5, 6, 255] {
                for len in [0u32, 1, 7, 8, 63, 64, 65, 16_384, 60_014, u32::MAX] {
                    for body_len in [0usize, 1, 8, 64] {
                        let mut raw = vec![version, kind];
                        raw.extend_from_slice(&0u16.to_be_bytes());
                        raw.extend_from_slice(&len.to_be_bytes());
                        raw.extend(std::iter::repeat_n(b'\xAB', body_len));
                        let _ = decode_exact(&raw);
                        checked += 1;
                    }
                }
            }
        }
        // Short buffers, including empty, which must hit ShortHeader.
        for n in 0..HEADER_LEN {
            assert!(matches!(
                decode_exact(&vec![0xFFu8; n]),
                Err(WireError::ShortHeader { .. })
            ));
            checked += 1;
        }
        assert!(checked > 1000, "the sweep did not actually run: {checked}");
    }
}
