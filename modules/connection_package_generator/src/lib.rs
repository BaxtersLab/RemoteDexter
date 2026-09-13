//! Block 10 removed `ConnectionPackageGenerator`, `build_connection_package`
//! and `HandshakeResult`.
//!
//! `ConnectionPackageGenerator` was an UNDECLARED STUB (Article VII): nothing
//! in the tree constructed it, and its `init` spawned a task whose whole body
//! was a 120-second timer and a comment reading "placeholder: could check for
//! upstream changes". The same shape as `module10::RemoteControl`, removed in
//! the same slice.
//!
//! `HandshakeResult` and `build_connection_package` were the dead chain Block 4
//! predicted: "Nothing constructs this any more. It survives only because
//! `build_connection_package` is still reachable from `clipboard` and
//! `multiplexer`; Block 10 removes that dead chain and this type with it."
//! Both of those crates are now deleted, so it did.
//!
//! What REMAINS is live and load-bearing: `ConnectionPackage`, `serialize` and
//! `deserialize` are used by `scp_consumer` and `session_manager`.

pub mod types;
pub mod utils;
pub mod serialize;
pub mod deserialize;

pub use types::{ConnectionPackage, ConnectionError};
pub use serialize::serialize_without_signature;
pub use deserialize::parse_connection_package;

