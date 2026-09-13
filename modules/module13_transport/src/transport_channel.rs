//! Transport channel for envelope communication

use tokio::sync::mpsc;

use crate::envelope::Envelope;
use crate::transport_error::TransportError;

/// Transport channel for sending/receiving envelopes
pub struct TransportChannel {
    tx: mpsc::Sender<Envelope>,
    rx: mpsc::Receiver<Envelope>,
}

impl TransportChannel {
    /// Create a new transport channel with the given buffer size
    pub fn new(buffer_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size);
        Self { tx, rx }
    }

    /// Send an envelope
    pub async fn send(&self, envelope: Envelope) -> Result<(), TransportError> {
        self.tx.send(envelope).await.map_err(|_| TransportError::ChannelClosed)
    }

    /// Receive an envelope
    pub async fn recv(&mut self) -> Result<Option<Envelope>, TransportError> {
        match self.rx.recv().await {
            Some(envelope) => Ok(Some(envelope)),
            None => Ok(None), // Channel closed
        }
    }

    /// Try to send an envelope without waiting
    pub fn try_send(&self, envelope: Envelope) -> Result<(), TransportError> {
        self.tx.try_send(envelope).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TransportError::BackpressureTimeout,
            mpsc::error::TrySendError::Closed(_) => TransportError::ChannelClosed,
        })
    }

    /// Check if the channel is closed
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Get the sender half
    pub fn sender(&self) -> mpsc::Sender<Envelope> {
        self.tx.clone()
    }

    /// Split into sender and receiver halves
    pub fn split(self) -> (mpsc::Sender<Envelope>, mpsc::Receiver<Envelope>) {
        (self.tx, self.rx)
    }
}

/// Transport sender (send-only half)
pub struct TransportSender {
    tx: mpsc::Sender<Envelope>,
}

impl TransportSender {
    /// Create from sender
    pub fn new(tx: mpsc::Sender<Envelope>) -> Self {
        Self { tx }
    }

    /// Send an envelope
    pub async fn send(&self, envelope: Envelope) -> Result<(), TransportError> {
        self.tx.send(envelope).await.map_err(|_| TransportError::ChannelClosed)
    }

    /// Try to send an envelope
    pub fn try_send(&self, envelope: Envelope) -> Result<(), TransportError> {
        self.tx.try_send(envelope).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TransportError::BackpressureTimeout,
            mpsc::error::TrySendError::Closed(_) => TransportError::ChannelClosed,
        })
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Transport receiver (receive-only half)
pub struct TransportReceiver {
    rx: mpsc::Receiver<Envelope>,
}

impl TransportReceiver {
    /// Create from receiver
    pub fn new(rx: mpsc::Receiver<Envelope>) -> Self {
        Self { rx }
    }

    /// Receive an envelope
    pub async fn recv(&mut self) -> Result<Option<Envelope>, TransportError> {
        match self.rx.recv().await {
            Some(envelope) => Ok(Some(envelope)),
            None => Ok(None),
        }
    }
}