//! Where the host's connections come from.
//!
//! The accept loop takes a stream and a label and does not care which of these
//! produced one. That is what lets the host be reachable two ways without two
//! paths through the host: everything downstream — the pre-auth bound, the
//! pinned Noise handshake, the session tasks — is identical either way.
//!
//! **This crate owns no wire protocol** (see the crate docs), so a source that
//! has to SPEAK one is implemented by the caller and injected through
//! [`DialOut`]. What lives here is the LISTENING source, because this crate is
//! also the only thing permitted to create a listener.

use crate::state::Reach;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::{TcpListener, TcpStream};

/// One peer: the socket, the address at the far end of it, and the label the
/// rest of the host knows it by.
///
/// The address is what the socket is REALLY connected to. For a listener that
/// is the client. For a dial-out it is the relay, because that is who the host
/// has a TCP connection with — the client is on the other side of a splice and
/// the host cannot see its address. Reporting a guess at the client's address
/// would be a fabricated fact in a security log.
pub type Peer = (TcpStream, SocketAddr, String);

/// The future [`PeerSource::next_peer`] returns.
pub type PeerFuture<'a> = Pin<Box<dyn Future<Output = Option<Peer>> + Send + 'a>>;

/// The future [`DialOut::connect`] returns.
pub type DialFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn PeerSource>, DialFailure>> + Send + 'a>>;

/// Whether dialling again could produce a different answer.
///
/// The controller cannot work this out for itself: it owns no wire protocol, so
/// all it would have to judge by is the text of a message. Whoever spoke the
/// protocol knows whether the relay was unreachable or whether it listened to
/// the credential and said no, and says which here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAdvice {
    /// A network failure: unreachable, closed mid-registration, timed out. The
    /// same credential may well work in a minute.
    Worthwhile,
    /// The relay answered and refused, or answered something this host cannot
    /// speak. **Retrying is a loop that hammers a relay with a credential it
    /// has already rejected**, and the operator never sees the reason because
    /// the next attempt overwrites it.
    Pointless,
}

/// Why a dial-out failed, and whether it is worth trying again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialFailure {
    /// Safe to display and safe to log. Never a token, never key material.
    pub message: String,
    /// Whether the controller should try this dial again.
    pub retry: RetryAdvice,
}

impl DialFailure {
    /// The relay could not be reached, or dropped the connection. Worth another
    /// attempt.
    pub fn unreachable(message: impl Into<String>) -> Self {
        DialFailure {
            message: message.into(),
            retry: RetryAdvice::Worthwhile,
        }
    }

    /// The relay answered and this host is not getting in. Retrying changes
    /// nothing until a human changes something.
    pub fn refused(message: impl Into<String>) -> Self {
        DialFailure {
            message: message.into(),
            retry: RetryAdvice::Pointless,
        }
    }

    /// Should the controller try again?
    pub fn worth_retrying(&self) -> bool {
        self.retry == RetryAdvice::Worthwhile
    }
}

/// The longest this host waits between dial attempts.
///
/// A ceiling, not a target: a relay that comes back should be found again
/// within a minute, and a relay that is down should not be dialled every second
/// by every host that has `dial_on_start` set.
pub const RETRY_CEILING: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to wait before attempt `attempt` (1-based: the first attempt does
/// not wait at all).
///
/// Doubling from one second, capped at [`RETRY_CEILING`]. Pure, so the schedule
/// is provable without a test that waits a minute to watch it — and the cap is
/// computed by saturating shift rather than `1 << attempt`, because a host left
/// retrying overnight reaches an attempt number that overflows the shift and a
/// panicking controller is a worse outcome than a slow one.
pub fn retry_delay(attempt: u32) -> std::time::Duration {
    if attempt <= 1 {
        return std::time::Duration::ZERO;
    }
    let doublings = attempt - 2;
    let secs = 1u64.checked_shl(doublings).unwrap_or(u64::MAX);
    std::time::Duration::from_secs(secs).min(RETRY_CEILING)
}

/// A source of incoming connections.
pub trait PeerSource: Send + 'static {
    /// The next peer, or `None` when this source is finished for good.
    ///
    /// **This future is dropped on cancellation.** The accept loop selects over
    /// it, so a Stop while waiting drops it mid-flight. For a listener that
    /// costs nothing. For a dial-out it may drop one client that was mid
    /// handover — the right outcome when the host is being torn down anyway,
    /// and the reason the relay frees an unredeemed ticket rather than holding
    /// it.
    fn next_peer(&mut self) -> PeerFuture<'_>;

    /// How this source makes the host reachable.
    fn reach(&self) -> Reach;
}

/// The listening source: one deliberately chosen interface, accepting.
///
/// **The only type in this crate that holds a listener.** A dial-out source
/// cannot become one, which is what keeps `bind`'s wildcard refusal from being
/// routed around rather than removed.
pub struct ListenSource {
    listener: TcpListener,
    bound: SocketAddr,
}

impl ListenSource {
    /// Wrap a listener that has already been bound to a validated address.
    pub fn new(listener: TcpListener, bound: SocketAddr) -> Self {
        ListenSource { listener, bound }
    }
}

impl PeerSource for ListenSource {
    fn next_peer(&mut self) -> PeerFuture<'_> {
        Box::pin(async move {
            loop {
                match self.listener.accept().await {
                    Ok((stream, addr)) => return Some((stream, addr, addr.to_string())),
                    // A failed accept is not the end of the listener. This is
                    // the old loop's `continue`, kept deliberately: returning
                    // `None` here would tear the whole host down on one
                    // transient error.
                    Err(_) => continue,
                }
            }
        })
    }

    fn reach(&self) -> Reach {
        Reach::Bound(self.bound)
    }
}

/// Opens the host's outbound path to a relay.
///
/// Injected at spawn time because this crate owns no wire protocol: the relay
/// control grammar is spoken by the caller. The controller knows only that
/// something can produce a source, or fail with a message safe to display and
/// safe to log.
pub trait DialOut: Send + 'static {
    /// Dial the relay, register, and return the live source.
    fn connect(&mut self) -> DialFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first attempt is immediate, then one second, doubling.
    ///
    /// The operator's own machine is the common case: a laptop that wakes up
    /// with no network and finds one a moment later should be back on the relay
    /// in about a second, not after a fixed minute.
    #[test]
    fn the_backoff_starts_immediately_and_then_doubles() {
        let schedule: Vec<u64> = (1..=8).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(
            schedule,
            vec![0, 1, 2, 4, 8, 16, 32, 60],
            "the retry schedule is not the documented 1s, 2s, 4s … capped at 60s"
        );
    }

    /// A host that has been retrying for a long time must keep retrying at the
    /// ceiling, and must not compute a delay of centuries — or panic working
    /// one out. `1u64 << 64` is a panic in debug and zero in release, which
    /// would turn an overnight outage into either a crash or a hot loop.
    #[test]
    fn the_backoff_is_capped_however_long_it_has_been_failing() {
        for attempt in [9u32, 64, 65, 1_000, u32::MAX] {
            assert_eq!(
                retry_delay(attempt),
                RETRY_CEILING,
                "attempt {attempt} did not wait exactly the ceiling"
            );
        }
    }

    /// The two failures are not the same event, and the difference is the whole
    /// point of the type: one is retried, the other is shown to a human.
    #[test]
    fn a_refusal_is_never_retried_and_an_unreachable_relay_always_is() {
        assert!(
            DialFailure::unreachable("could not reach the relay: connection refused")
                .worth_retrying(),
            "a network failure was treated as final — the relay coming back would never be noticed"
        );
        assert!(
            !DialFailure::refused("the relay refused this host: not enrolled").worth_retrying(),
            "a refused credential would be retried forever, hammering the relay and hiding the reason from the operator"
        );
    }

    /// A dial-out source must never report a bound address, because it binds
    /// nothing. If it ever did, `is_listening()` would be true for a host with
    /// no listener — and `scripts/vm-host-console-proof.sh` proves the absence
    /// of a listener with `ss`, not the absence of this field.
    #[test]
    fn a_dial_out_reach_is_never_a_bound_address() {
        let reach = Reach::ViaRelay {
            relay: "203.0.113.9:9443".parse().unwrap(),
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        };
        assert_eq!(
            reach.bound(),
            None,
            "dial-out reported a bound address — it binds nothing, and reporting one would make a host with no listener look like it is listening"
        );
    }

    #[test]
    fn a_listening_reach_reports_exactly_what_was_bound() {
        let addr: SocketAddr = "192.168.1.20:8082".parse().unwrap();
        assert_eq!(Reach::Bound(addr).bound(), Some(addr));
    }
}
