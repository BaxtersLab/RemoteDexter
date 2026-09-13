pub mod framed_stream;
pub mod envelope;
pub mod backpressure_level;
pub mod transport_error;
pub mod transport_channel;
pub mod transport_engine;
pub mod invariants;

// Type aliases for session layer convenience
pub use envelope::FrameDataEnvelope as FrameEnvelope;
pub use envelope::ControlEnvelope;
pub use transport_engine::AsyncTransportEngine as TransportEngine;
pub use transport_engine::{AsyncTransportSender, AsyncTransportReceiver, new_async_transport};