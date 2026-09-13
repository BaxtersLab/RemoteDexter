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
    Pin<Box<dyn Future<Output = Result<Box<dyn PeerSource>, String>> + Send + 'a>>;

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
