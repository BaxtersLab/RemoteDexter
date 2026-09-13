//! The host lifecycle, and the commands and events that move it.

use crate::bind::BindRejection;
use std::net::SocketAddr;

/// How the host is reachable.
///
/// Two routes exist and they are not interchangeable. Keeping them one type,
/// rather than a `SocketAddr` that sometimes means something else, is what stops
/// "reachable" from quietly implying "listening".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Bound to one deliberately chosen interface and accepting.
    ///
    /// **The only variant in which a listener exists.**
    Bound(SocketAddr),
    /// Dialled out to a relay, holding a control connection.
    ///
    /// **No listener exists in this mode.** The host opened an OUTBOUND
    /// connection and is told over it when to open another; nothing is
    /// accepting. [`HostState::bound`] is `None` here because there is nothing
    /// to report — not because it was left out.
    ///
    /// Reporting the relay's address as if it were a bound one would be a
    /// synthetic value standing in for something that does not exist, and would
    /// make [`HostState::is_listening`] true for a host with no listener. That
    /// is the one property `scripts/vm-host-console-proof.sh` checks with `ss`.
    ViaRelay {
        /// The relay this host dialled. Never bound, only connected to.
        relay: SocketAddr,
        /// The session id the relay issued. The invite will carry this instead
        /// of a LAN address.
        session: String,
    },
}

impl Reach {
    /// The address BOUND, if this route binds one. `None` for dial-out.
    pub fn bound(&self) -> Option<SocketAddr> {
        match self {
            Reach::Bound(a) => Some(*a),
            Reach::ViaRelay { .. } => None,
        }
    }

    /// What the UI shows for where the host can be reached.
    pub fn describe(&self) -> String {
        match self {
            Reach::Bound(a) => a.to_string(),
            Reach::ViaRelay { relay, .. } => format!("via relay {relay}"),
        }
    }
}

/// Where the host is. **`Stopped` means no listener exists** — not a listener
/// that refuses, not a listener bound to a dead address. The socket is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostState {
    /// Nothing is running. No socket, no capture, no input devices.
    Stopped,
    /// A `Start` is in progress: the address has been validated but the
    /// listener is not accepting yet.
    Starting,
    /// Serving and reachable, no peer connected. This is the state in which a
    /// pairing QR is meaningful.
    Pairable {
        /// How the host is reachable: a bound interface, or a relay it dialled.
        reach: Reach,
    },
    /// Serving, with `peers` connected.
    Connected {
        /// How the host is reachable.
        reach: Reach,
        /// How many peers are connected right now.
        peers: usize,
    },
    /// A `Stop` is in progress: accept has been cancelled and teardown is
    /// running. The next state is always `Stopped`.
    Stopping,
    /// Something failed. Carries a message that is safe to display and log.
    Error {
        /// Redacted, human-readable. Never a token or key material.
        message: String,
    },
}

impl HostState {
    /// The address currently bound, if any. `None` in every state that has no
    /// listener — which is the property most of the tests are about.
    pub fn bound(&self) -> Option<SocketAddr> {
        match self {
            HostState::Pairable { reach } | HostState::Connected { reach, .. } => reach.bound(),
            _ => None,
        }
    }

    /// How the host is reachable, if it is.
    pub fn reach(&self) -> Option<&Reach> {
        match self {
            HostState::Pairable { reach } | HostState::Connected { reach, .. } => Some(reach),
            _ => None,
        }
    }

    /// **True only while a LISTENER exists.**
    ///
    /// Deliberately FALSE for a host that dialled out: it is serving, but it is
    /// accepting nothing and no port is open. Ask [`HostState::is_running`] for
    /// "is the host working"; this one answers a narrower question that the
    /// console proof depends on.
    pub fn is_listening(&self) -> bool {
        self.bound().is_some()
    }

    /// True while the host is serving, by either route.
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            HostState::Pairable { .. } | HostState::Connected { .. }
        )
    }

    /// Connected peer count. Zero in every state but `Connected`.
    pub fn peers(&self) -> usize {
        match self {
            HostState::Connected { peers, .. } => *peers,
            _ => 0,
        }
    }

    /// Short label for the UI's status line.
    pub fn label(&self) -> &'static str {
        match self {
            HostState::Stopped => "Stopped",
            HostState::Starting => "Starting",
            HostState::Pairable { .. } => "Pairable",
            HostState::Connected { .. } => "Connected",
            HostState::Stopping => "Stopping",
            HostState::Error { .. } => "Error",
        }
    }
}

/// A minted invitation, as much of it as the UI is allowed to see.
///
/// **The token is deliberately absent.** It exists in exactly one place: inside
/// the QR modules below. The UI draws them; it never reads them, never formats
/// them into a string, and cannot log them. A `Debug` on this type prints the
/// module count, not a credential.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteView {
    /// Side length of the QR in modules, including the quiet zone.
    pub qr_size: usize,
    /// `qr_size * qr_size` booleans, `true` = dark.
    pub qr_modules: Vec<bool>,
    /// Short non-secret handle for correlating log lines.
    pub token_fingerprint: String,
    /// Unix seconds at which this invitation stops being valid.
    pub expires_at: u64,
}

impl std::fmt::Debug for InviteView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never renders the modules: they ARE the token.
        f.debug_struct("InviteView")
            .field("qr_size", &self.qr_size)
            .field("token_fingerprint", &self.token_fingerprint)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What the UI may ask the host to do. This is the *entire* local command
/// surface; there is no other way to affect the host, and none of these can be
/// triggered remotely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    /// Bind exactly this address and begin accepting. Rejected if a listener
    /// already exists — restarting on a new address is Stop then Start, so the
    /// old socket is provably gone before the new one appears.
    Start {
        /// The chosen interface and port.
        bind: SocketAddr,
    },
    /// Dial the configured relay and serve through it. **Binds nothing.**
    ///
    /// Refused by a controller built without a dial-out, rather than falling
    /// back to binding: the two are different exposures and the operator chose
    /// one of them. Rejected while already running, for the same reason `Start`
    /// is — changing route is Stop then Start, so the old one is provably gone.
    StartViaRelay,
    /// Drop the listener or the relay connection, every session, capture, and
    /// input devices, and wait for the tasks to exit.
    Stop,
    /// Mint a pairing invitation for the address already bound.
    ///
    /// Only meaningful while listening: there is no address to invite anyone to
    /// otherwise, and an invite minted against a guess is how the previous
    /// implementation ended up probing `8.8.8.8` for one.
    CreateInvite,
    /// Disconnect a live peer immediately.
    ///
    /// This is a *live-session* disconnect. Durable revocation — tombstoning a
    /// device's public key so it can never reconnect — is Block 9, and needs a
    /// paired-device store that does not exist yet.
    RevokePeer {
        /// Which connected peer, by the label reported in `PeerConnected`.
        peer: String,
    },
    /// Tear everything down and end the controller thread.
    Shutdown,
}

/// What the host tells the UI. Every variant is safe to render and safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// The lifecycle moved.
    StateChanged(HostState),
    /// A peer connected. `peer` is an address label, never a credential.
    PeerConnected {
        /// Address label for the UI's device list.
        peer: String,
        /// Peer count after this connection.
        count: usize,
    },
    /// A peer disconnected.
    PeerDisconnected {
        /// Address label.
        peer: String,
        /// Peer count after this disconnection.
        count: usize,
    },
    /// A pairing invitation is ready.
    InviteReady(InviteView),
    /// Something went wrong. **Redacted by construction**: the controller only
    /// ever puts rule names and typed reasons in here, never an address it was
    /// given, a token, or key bytes.
    Fault {
        /// Safe to display and log.
        message: String,
    },
}

impl HostEvent {
    /// Build the `Fault` for a refused bind address. Note what is absent: the
    /// address itself. The user typed it, so echoing it back teaches nothing,
    /// and a log line is a worse place for it than the screen.
    pub fn bind_rejected(reason: BindRejection) -> Self {
        HostEvent::Fault {
            message: format!("bind refused: {}", reason.reason()),
        }
    }
}
