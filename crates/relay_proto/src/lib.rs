//! The control grammar spoken before a splice begins, and nothing after it.
//!
//! Two sockets exchange a few small frames to say who they are and which
//! session they want. After that the relay copies raw bytes and never looks at
//! them again — so this grammar is the ENTIRE attack surface a stranger can
//! reach by connecting to the port.
//!
//! It is deliberately tiny for that reason, and bounded before anything parses:
//! a length prefix that is checked against [`MAX_CONTROL_FRAME`] first, so a
//! hostile peer cannot make the relay allocate by claiming a huge frame. The
//! same instinct as `wire::decode_exact`, which bounds depth before building a
//! tree.

use serde::{Deserialize, Serialize};

/// The largest control frame the relay will read, before anything parses it.
///
/// Registration carries a public key and a signature; joining carries a session
/// id. None of that approaches a kilobyte. The cap exists so a peer cannot
/// announce a 4 GiB frame and have the relay believe it.
pub const MAX_CONTROL_FRAME: usize = 4096;

/// Why a control frame was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The length prefix exceeds [`MAX_CONTROL_FRAME`].
    TooLarge(usize),
    /// The length prefix is zero — there is no such frame.
    Empty,
    /// The body is not valid UTF-8 JSON, or not a frame this version knows.
    Malformed,
    /// A field the frame's own type requires is missing or the wrong shape.
    MissingField(&'static str),
}

impl FrameError {
    /// What the peer is told. Deliberately coarse: a peer that guesses wrong
    /// learns that it was refused and roughly which contract it broke, and
    /// nothing about the relay's state. The same reasoning as the host's
    /// `pair_denied`, which carries no detail on the wire.
    pub fn public_reason(&self) -> &'static str {
        match self {
            FrameError::TooLarge(_) => "frame too large",
            FrameError::Empty => "empty frame",
            FrameError::Malformed => "malformed frame",
            FrameError::MissingField(_) => "malformed frame",
        }
    }
}

/// Every frame the relay understands. Anything else is [`FrameError::Malformed`].
///
/// `v` is carried on the two frames a peer sends FIRST, so a version mismatch
/// is refused at the door rather than halfway through an exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ControlFrame {
    /// Host → relay. "I am this identity and I want to accept sessions."
    Register {
        v: u8,
        /// Base64 Ed25519 public key. The relay stores only public halves.
        host_pub: String,
    },
    /// Relay → host. A nonce to sign, so registration cannot be replayed.
    Challenge { nonce: String },
    /// Host → relay. Base64 Ed25519 signature over the challenge nonce.
    Prove { sig: String },
    /// Relay → host. Registration accepted; this is the session to publish.
    Registered { session: String },
    /// Client → relay. "Splice me to this session."
    Join { v: u8, session: String },
    /// Relay → client. Accepted; everything after this frame is opaque.
    Joined,
    /// Relay → host, on the CONTROL connection. "A client is waiting for you;
    /// dial back with this ticket."
    ///
    /// The host holds one control connection for the life of the invite and is
    /// told over it when to open a data connection. That is what lets one
    /// session id stay valid across reconnections, and it is why the relay
    /// never has to multiplex — which would mean parsing session framing, the
    /// one thing this crate must not do.
    ClientWaiting { ticket: String },
    /// Host → relay, the FIRST frame on a fresh DATA connection.
    ///
    /// Carries `v` because it opens a connection: a version mismatch is refused
    /// at the door here exactly as it is for `Register` and `Join`.
    Attach { v: u8, ticket: String },
    /// Relay → host. The data connection is joined; everything after is opaque.
    Attached,
    /// Relay → host, on the control connection. Keepalive.
    ///
    /// A dialled-out control connection sits idle between clients, and idle TCP
    /// through a home NAT is reaped without either end being told. Without this
    /// the host believes it is reachable while the relay holds a session nobody
    /// can ever attach to.
    Ping,
    /// Host → relay. The answer to [`ControlFrame::Ping`].
    Pong,
    /// Relay → either. Refused, with a coarse reason.
    Denied { why: String },
}

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u8 = 1;

/// Decode one control frame from a body that has ALREADY been length-checked.
///
/// Separate from the length check on purpose: the cap must be applied to the
/// prefix before a single byte of body is read, and a function that takes an
/// already-read body cannot enforce that. [`check_len`] is the half that runs
/// first.
pub fn decode(body: &[u8]) -> Result<ControlFrame, FrameError> {
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let frame: ControlFrame = serde_json::from_slice(body).map_err(|_| FrameError::Malformed)?;
    match &frame {
        ControlFrame::Register { host_pub, .. } if host_pub.is_empty() => {
            Err(FrameError::MissingField("host_pub"))
        }
        ControlFrame::Prove { sig } if sig.is_empty() => Err(FrameError::MissingField("sig")),
        ControlFrame::Join { session, .. } if session.is_empty() => {
            Err(FrameError::MissingField("session"))
        }
        ControlFrame::Attach { ticket, .. } if ticket.is_empty() => {
            Err(FrameError::MissingField("ticket"))
        }
        ControlFrame::ClientWaiting { ticket } if ticket.is_empty() => {
            Err(FrameError::MissingField("ticket"))
        }
        _ => Ok(frame),
    }
}

/// Encode one control frame. Infallible for the frames this crate constructs.
pub fn encode(frame: &ControlFrame) -> Vec<u8> {
    serde_json::to_vec(frame).expect("ControlFrame is always serialisable")
}

/// Whether a declared frame length may be read at all.
///
/// **Called on the length prefix, before the body is read.** That ordering is
/// the whole point: checking after reading means the allocation already
/// happened, which is the denial-of-service this bound exists to refuse.
pub fn check_len(declared: usize) -> Result<usize, FrameError> {
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge(declared));
    }
    Ok(declared)
}

/// Whether this build can speak to a peer announcing version `v`.
pub fn version_accepted(v: u8) -> bool {
    v == PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_over_the_cap_is_refused_before_any_body_is_read() {
        assert_eq!(
            check_len(MAX_CONTROL_FRAME + 1),
            Err(FrameError::TooLarge(MAX_CONTROL_FRAME + 1))
        );
        // The boundary itself is allowed; off-by-one here would refuse a legal
        // frame and be found only by a peer that happened to hit it exactly.
        assert_eq!(check_len(MAX_CONTROL_FRAME), Ok(MAX_CONTROL_FRAME));
    }

    #[test]
    fn a_zero_length_frame_is_refused() {
        assert_eq!(check_len(0), Err(FrameError::Empty));
        assert_eq!(decode(b""), Err(FrameError::Empty));
    }

    /// A stranger reaching the port must not be able to make the relay allocate.
    #[test]
    fn an_enormous_declared_length_cannot_be_read() {
        for huge in [MAX_CONTROL_FRAME + 1, 1 << 20, usize::MAX] {
            assert!(
                matches!(check_len(huge), Err(FrameError::TooLarge(_))),
                "a declared length of {huge} was accepted"
            );
        }
    }

    #[test]
    fn register_round_trips() {
        let f = ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: "abc".into(),
        };
        assert_eq!(decode(&encode(&f)), Ok(f));
    }

    #[test]
    fn join_round_trips() {
        let f = ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: "s-1".into(),
        };
        assert_eq!(decode(&encode(&f)), Ok(f));
    }

    #[test]
    fn garbage_is_malformed_rather_than_a_panic() {
        for junk in [
            &b"{"[..],
            &b"not json at all"[..],
            &b"[]"[..],
            &b"{\"t\":\"nonsense\"}"[..],
            &[0xff, 0xfe, 0xfd][..],
        ] {
            assert_eq!(decode(junk), Err(FrameError::Malformed), "{junk:?}");
        }
    }

    /// An empty required field is a malformed frame, not an empty identity.
    #[test]
    fn empty_required_fields_are_refused() {
        let empty_pub = encode(&ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: String::new(),
        });
        assert_eq!(
            decode(&empty_pub),
            Err(FrameError::MissingField("host_pub"))
        );

        let empty_session = encode(&ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: String::new(),
        });
        assert_eq!(
            decode(&empty_session),
            Err(FrameError::MissingField("session"))
        );
    }

    /// A refusal tells the peer it was refused and nothing about relay state.
    #[test]
    fn refusal_reasons_carry_no_detail() {
        assert_eq!(
            FrameError::TooLarge(1 << 30).public_reason(),
            "frame too large"
        );
        assert_eq!(
            FrameError::MissingField("host_pub").public_reason(),
            "malformed frame"
        );
        // The field name is kept for OUR logs and must not reach the peer.
        assert!(!FrameError::MissingField("host_pub")
            .public_reason()
            .contains("host_pub"));
    }

    #[test]
    fn only_this_protocol_version_is_accepted() {
        assert!(version_accepted(PROTOCOL_VERSION));
        for other in [0u8, PROTOCOL_VERSION + 1, 255] {
            assert!(!version_accepted(other), "version {other} was accepted");
        }
    }

    #[test]
    fn the_dial_out_frames_round_trip() {
        for f in [
            ControlFrame::ClientWaiting {
                ticket: "abc".into(),
            },
            ControlFrame::Attach {
                v: PROTOCOL_VERSION,
                ticket: "abc".into(),
            },
            ControlFrame::Attached,
            ControlFrame::Ping,
            ControlFrame::Pong,
        ] {
            assert_eq!(decode(&encode(&f)), Ok(f));
        }
    }

    /// An attach with no ticket is malformed, not "a ticket that does not
    /// match" — it must never reach the table as an empty key.
    #[test]
    fn an_attach_without_a_ticket_is_malformed() {
        let f = ControlFrame::Attach {
            v: PROTOCOL_VERSION,
            ticket: String::new(),
        };
        assert_eq!(decode(&encode(&f)), Err(FrameError::MissingField("ticket")));
        let f = ControlFrame::ClientWaiting {
            ticket: String::new(),
        };
        assert_eq!(decode(&encode(&f)), Err(FrameError::MissingField("ticket")));
    }

    /// Every frame that OPENS a connection carries the version, so a mismatch
    /// is refused at the door rather than halfway through an exchange. Attach
    /// opens the data connection and is in that set.
    #[test]
    fn every_connection_opening_frame_carries_a_version() {
        let opening = [
            encode(&ControlFrame::Register {
                v: PROTOCOL_VERSION,
                host_pub: "k".into(),
            }),
            encode(&ControlFrame::Join {
                v: PROTOCOL_VERSION,
                session: "s".into(),
            }),
            encode(&ControlFrame::Attach {
                v: PROTOCOL_VERSION,
                ticket: "t".into(),
            }),
        ];
        for body in opening {
            let text = String::from_utf8(body).unwrap();
            assert!(
                text.contains("\"v\":"),
                "a connection-opening frame lost its version field: {text}"
            );
        }
    }

    /// A ticket is not carried on any frame a STRANGER sends unprompted. It
    /// reaches the host over the control connection it already authenticated,
    /// and comes back on `Attach`. Nothing else in the grammar accepts one.
    #[test]
    fn only_attach_brings_a_ticket_back_to_the_relay() {
        let peer_to_relay_with_ticket = encode(&ControlFrame::Attach {
            v: PROTOCOL_VERSION,
            ticket: "t".into(),
        });
        assert!(matches!(
            decode(&peer_to_relay_with_ticket),
            Ok(ControlFrame::Attach { .. })
        ));
        // Join is the other peer-initiated frame and takes a SESSION, not a
        // ticket: a ticket sent there is simply an unknown session id.
        let f = ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: "t".into(),
        };
        assert!(matches!(decode(&encode(&f)), Ok(ControlFrame::Join { .. })));
    }
}
