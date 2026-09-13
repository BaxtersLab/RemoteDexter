// greenlight: no allow band-aids
mod interfaces;
pub mod logical_session;
pub mod connection_manager;

pub use interfaces::{Module5Reader, EventSource, Module4Connector};
pub use logical_session::{LogicalSession, LogicalStatus, LogicalError};
pub use connection_manager::{ConnectionManager, RekeyPolicy};

// Public re-exports for integration tests and consumers.
