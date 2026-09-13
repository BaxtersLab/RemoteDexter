//! Transport engine for envelope-based communication

use std::io::{Read, Write};
use tokio::sync::mpsc;

use crate::framed_stream::FramedStream;
use crate::envelope::{Envelope, tags};
use crate::backpressure_level::BackpressureLevel;
use crate::transport_error::TransportError;

/// Transport engine for sending/receiving envelopes over framed streams
pub struct TransportEngine<T> {
    framed_stream: FramedStream<T>,
    backpressure_level: BackpressureLevel,
}

impl<T> TransportEngine<T>
where
    T: Read + Write,
{
    /// Create a new transport engine
    pub fn new(stream: T) -> Self {
        Self {
            framed_stream: FramedStream::new(stream),
            backpressure_level: BackpressureLevel::Ready,
        }
    }

    /// Send an envelope
    pub fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), TransportError> {
        // Validate tag
        if !Envelope::is_valid_tag(envelope.tag) {
            return Err(TransportError::InvalidTag { tag: envelope.tag });
        }

        // Encode envelope to bytes
        let data = envelope.encode();

        // Send framed data
        self.framed_stream.write_frame(&data).map_err(TransportError::from)
    }

    /// Receive an envelope
    pub fn receive_envelope(&mut self) -> Result<Option<Envelope>, TransportError> {
        // Read framed data
        let data = match self.framed_stream.read_frame()? {
            Some(data) => data,
            None => return Ok(None), // EOF
        };

        // Decode envelope
        let envelope = Envelope::decode(data).ok_or_else(|| {
            TransportError::ProtocolError {
                message: "Failed to decode envelope".to_string(),
            }
        })?;

        // Handle special envelopes
        match envelope.tag {
            tags::BACKPRESSURE_UPDATE => {
                if let Some(update) = crate::envelope::BackpressureUpdateEnvelope::decode(&envelope) {
                    if let Some(level) = BackpressureLevel::from_u8(update.level) {
                        self.backpressure_level = level;
                    } else {
                        return Err(TransportError::InvalidBackpressureLevel { level: update.level });
                    }
                }
            }
            _ => {}
        }

        Ok(Some(envelope))
    }

    /// Send backpressure update
    pub fn send_backpressure_update(&mut self, level: BackpressureLevel) -> Result<(), TransportError> {
        let update = crate::envelope::BackpressureUpdateEnvelope::new(level.to_u8());
        self.send_envelope(&update.encode())
    }

    /// Get current backpressure level
    pub fn backpressure_level(&self) -> BackpressureLevel {
        self.backpressure_level
    }

    /// Check if sending is allowed based on backpressure
    pub fn can_send(&self) -> bool {
        self.backpressure_level.can_send()
    }

    /// Send frame data
    pub fn send_frame_data(&mut self, frame_data: bytes::Bytes) -> Result<(), TransportError> {
        let envelope = crate::envelope::FrameDataEnvelope::new(frame_data).encode();
        self.send_envelope(&envelope)
    }

    /// Send reset signal
    pub fn send_reset(&mut self) -> Result<(), TransportError> {
        let envelope = crate::envelope::ResetEnvelope::new().encode();
        self.send_envelope(&envelope)
    }

    /// Send force keyframe signal
    pub fn send_force_keyframe(&mut self) -> Result<(), TransportError> {
        let envelope = crate::envelope::ForceKeyframeEnvelope::new().encode();
        self.send_envelope(&envelope)
    }

    /// Send error message
    pub fn send_error_message(&mut self, message: String) -> Result<(), TransportError> {
        let envelope = crate::envelope::ErrorMessageEnvelope::new(message).encode();
        self.send_envelope(&envelope)
    }

    /// Send heartbeat
    pub fn send_heartbeat(&mut self) -> Result<(), TransportError> {
        let envelope = crate::envelope::HeartbeatEnvelope::new().encode();
        self.send_envelope(&envelope)
    }

    /// Get reference to inner stream
    pub fn get_ref(&self) -> &T {
        self.framed_stream.get_ref()
    }

    /// Get mutable reference to inner stream
    pub fn get_mut(&mut self) -> &mut T {
        self.framed_stream.get_mut()
    }

    /// Consume the engine and return the inner stream
    pub fn into_inner(self) -> T {
        self.framed_stream.into_inner()
    }
}

/// Async transport engine for channel-based communication
pub struct AsyncTransportEngine {
    sender: mpsc::Sender<Envelope>,
    receiver: mpsc::Receiver<Envelope>,
    backpressure_level: BackpressureLevel,
}

impl AsyncTransportEngine {
    /// Create a new async transport engine
    pub fn new(buffer_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_size);
        Self {
            sender,
            receiver,
            backpressure_level: BackpressureLevel::Ready,
        }
    }

    /// Send an envelope asynchronously
    pub async fn send_envelope(&self, envelope: Envelope) -> Result<(), TransportError> {
        // Validate tag
        if !Envelope::is_valid_tag(envelope.tag) {
            return Err(TransportError::InvalidTag { tag: envelope.tag });
        }

        self.sender.send(envelope).await.map_err(|_| TransportError::ChannelClosed)
    }

    /// Receive an envelope asynchronously
    pub async fn receive_envelope(&mut self) -> Result<Option<Envelope>, TransportError> {
        match self.receiver.recv().await {
            Some(envelope) => {
                // Handle backpressure updates
                if envelope.tag == tags::BACKPRESSURE_UPDATE {
                    if let Some(update) = crate::envelope::BackpressureUpdateEnvelope::decode(&envelope) {
                        if let Some(level) = BackpressureLevel::from_u8(update.level) {
                            self.backpressure_level = level;
                        } else {
                            return Err(TransportError::InvalidBackpressureLevel { level: update.level });
                        }
                    }
                }
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    /// Get current backpressure level
    pub fn backpressure_level(&self) -> BackpressureLevel {
        self.backpressure_level
    }

    /// Check if sending is allowed
    pub fn can_send(&self) -> bool {
        self.backpressure_level.can_send()
    }

    /// Send a control envelope asynchronously
    pub async fn send_control(&self, control: crate::envelope::ControlEnvelope) -> Result<(), TransportError> {
        let envelope = control.encode();
        self.send_envelope(envelope).await
    }

    /// Get sender for external use
    pub fn sender(&self) -> mpsc::Sender<Envelope> {
        self.sender.clone()
    }
}

// ---------------------------------------------------------------------------
// Split async transport (F11)
// ---------------------------------------------------------------------------

/// Async transport sender — cloneable, no mutex needed for concurrent sends
#[derive(Clone)]
pub struct AsyncTransportSender {
    inner: mpsc::Sender<Envelope>,
}

impl AsyncTransportSender {
    /// Send an envelope asynchronously
    pub async fn send_envelope(&self, envelope: Envelope) -> Result<(), TransportError> {
        if !Envelope::is_valid_tag(envelope.tag) {
            return Err(TransportError::InvalidTag { tag: envelope.tag });
        }
        self.inner.send(envelope).await.map_err(|_| TransportError::ChannelClosed)
    }

    /// Send a heartbeat
    pub async fn send_heartbeat(&self) -> Result<(), TransportError> {
        self.send_envelope(crate::envelope::HeartbeatEnvelope::new().encode()).await
    }

    /// Send a control envelope
    pub async fn send_control(&self, control: crate::envelope::ControlEnvelope) -> Result<(), TransportError> {
        self.send_envelope(control.encode()).await
    }
}

/// Async transport receiver — owns the receive half and backpressure tracker
pub struct AsyncTransportReceiver {
    inner: mpsc::Receiver<Envelope>,
    backpressure: BackpressureLevel,
}

impl AsyncTransportReceiver {
    /// Receive an envelope asynchronously
    pub async fn receive_envelope(&mut self) -> Result<Option<Envelope>, TransportError> {
        match self.inner.recv().await {
            Some(envelope) => {
                if envelope.tag == tags::BACKPRESSURE_UPDATE {
                    if let Some(update) = crate::envelope::BackpressureUpdateEnvelope::decode(&envelope) {
                        if let Some(level) = BackpressureLevel::from_u8(update.level) {
                            self.backpressure = level;
                        } else {
                            return Err(TransportError::InvalidBackpressureLevel { level: update.level });
                        }
                    }
                }
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    /// Get current backpressure level
    pub fn backpressure_level(&self) -> BackpressureLevel {
        self.backpressure
    }

    /// Check if sending is allowed based on backpressure
    pub fn can_send(&self) -> bool {
        self.backpressure.can_send()
    }
}

/// Create a new split async transport pair
pub fn new_async_transport(buffer_size: usize) -> (AsyncTransportSender, AsyncTransportReceiver) {
    let (tx, rx) = mpsc::channel(buffer_size);
    (
        AsyncTransportSender { inner: tx },
        AsyncTransportReceiver { inner: rx, backpressure: BackpressureLevel::Ready },
    )
}