//! Framed stream with length-prefix and CRC32 integrity

use std::io::{self, Read, Write};
use bytes::{Buf, Bytes, BytesMut};
use crc32fast::Hasher;

/// Maximum frame size (64KB)
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Minimum frame size (header only)
pub const MIN_FRAME_SIZE: usize = 8;

/// Frame header: length (4 bytes) + CRC32 (4 bytes)
const HEADER_SIZE: usize = 8;

/// Framed stream reader/writer
pub struct FramedStream<T> {
    inner: T,
    buffer: BytesMut,
}

impl<T> FramedStream<T>
where
    T: Read + Write,
{
    /// Create a new framed stream
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
        }
    }

    /// Write a frame with length prefix and CRC32
    pub fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Frame size {} exceeds maximum {}", data.len(), MAX_FRAME_SIZE),
            ));
        }

        // Calculate CRC32 of the data
        let mut hasher = Hasher::new();
        hasher.update(data);
        let crc = hasher.finalize();

        // Write header: length (big-endian) + CRC32 (big-endian)
        let length = data.len() as u32;
        self.inner.write_all(&length.to_be_bytes())?;
        self.inner.write_all(&crc.to_be_bytes())?;

        // Write data
        self.inner.write_all(data)?;
        self.inner.flush()?;

        Ok(())
    }

    /// Read a complete frame
    pub fn read_frame(&mut self) -> io::Result<Option<Bytes>> {
        // Ensure we have at least the header
        while self.buffer.len() < HEADER_SIZE {
            let mut temp_buf = [0u8; 1024];
            let n = self.inner.read(&mut temp_buf)?;
            if n == 0 {
                // EOF
                return Ok(None);
            }
            self.buffer.extend_from_slice(&temp_buf[..n]);
        }

        // Parse header
        let length = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_be_bytes(self.buffer[4..8].try_into().unwrap());

        if length > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame size {} exceeds maximum {}", length, MAX_FRAME_SIZE),
            ));
        }

        if length < MIN_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame size {} below minimum {}", length, MIN_FRAME_SIZE),
            ));
        }

        // Ensure we have the full frame
        let total_frame_size = HEADER_SIZE + length;
        while self.buffer.len() < total_frame_size {
            let mut temp_buf = [0u8; 1024];
            let n = self.inner.read(&mut temp_buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading frame data",
                ));
            }
            self.buffer.extend_from_slice(&temp_buf[..n]);
        }

        // Extract data and verify CRC
        let data_start = HEADER_SIZE;
        let data_end = HEADER_SIZE + length;
        let data = &self.buffer[data_start..data_end];

        // Verify CRC32
        let mut hasher = Hasher::new();
        hasher.update(data);
        let actual_crc = hasher.finalize();

        if actual_crc != expected_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRC32 mismatch: expected {:08x}, got {:08x}", expected_crc, actual_crc),
            ));
        }

        // Return the data and consume from buffer
        let result = Bytes::copy_from_slice(data);
        self.buffer.advance(total_frame_size);

        Ok(Some(result))
    }

    /// Get reference to inner stream
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get mutable reference to inner stream
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the framed stream and return the inner stream
    pub fn into_inner(self) -> T {
        self.inner
    }
}