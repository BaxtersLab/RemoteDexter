//! # pairing
//!
//! **One** pairing implementation: a signed, versioned invite carrying a
//! one-use 256-bit token, rendered to an in-memory QR for the address the host
//! is already bound to.
//!
//! It replaces five crates — `module17_bootstrap_invite`, `module23_wifi_beacon`,
//! `module22_nfc_writer`, `qr_bootstrap`, `qr_handshake` — which between them
//! implemented two unused pairing models, a UDP broadcaster that disclosed the
//! live token to the whole subnet every five seconds, an NFC writer that
//! reported success before attempting the write, and a Bluetooth transport that
//! did not exist.
//!
//! ## The design constraint that shapes this crate
//!
//! **It cannot have side effects.** Not "does not", *cannot*: there is no
//! dependency here on `tokio`, on `std::process`, on any socket type, or on any
//! filesystem API. `create_invite` receives an already-bound address and
//! returns a value. The compiler enforces what the previous implementation left
//! to intent.
//!
//! ## Reading order
//!
//! - [`identity`] — the durable Ed25519 signing key
//! - [`token`] — 256 bits, one use, sixty seconds, hash-only retention
//! - [`invite`] — the v4 schema, what the signature covers, and the strict v3 decoder
//! - [`qr`] — modules in memory, never a file
//! - [`service`] — the mint/redeem/revoke surface the host drives

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod devices;
pub mod identity;
pub mod invite;
pub mod qr;
pub mod service;
pub mod token;

pub use identity::{identity_b64, load_or_create, IdentityError};
pub use invite::{
    decode, field_carries_separator, signature_is_valid, DecodeError, Decoded, DualInvite,
    LegacyInvite, RelayInvite, SignedInvite, CANONICAL_SEPARATOR, DUAL_INVITE_VERSION, INVITE_KIND,
    INVITE_VERSION, LEGACY_INVITE_VERSION, RELAY_INVITE_VERSION, SESSION_PROTOCOL,
};
pub use qr::QrBitmap;
pub use service::{
    DualInvitation, Invitation, MintError, PairingService, RelayInvitation, CAP_CONTROL, CAP_VIEW,
};
pub use token::{RedeemError, RedemptionHandle, Token, TokenDigest, TokenStore, TOKEN_TTL};
