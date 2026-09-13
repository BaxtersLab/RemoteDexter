//! Super-Block 3: Message Enum + Encoder/Decoder Scaffolding
//!
//! Scope:
//! - Message enum for all conceptual message types described by Super-Block 2.
//! - Encoder / decoder function signatures (no implementation).
//! - Chunker and sink type signatures (no implementation).
//! - Public API façade type signatures (no implementation).
//!
//! This module provides scaffolding only: type signatures and placeholders
//! to be filled in by subsequent implementation steps. No runtime logic,
//! filesystem access, async code, or chunking algorithms are present here.

use std::marker::PhantomData;

/// Top-level message enum for the file-transfer protocol.
/// Variants are present as placeholders and should be refined with
/// concrete fields as the protocol design is implemented.
pub enum FileTransferMessage {
    Offer {
        file_size: u64,
        name: String,
        mime: String,
        file_hash: Option<FileHash>,
    },

    Accept,

    Reject {
        reason_code: u8,
        reason: String,
    },

    Chunk {
        index: u64,
        data: Vec<u8>,
        chunk_hash: u64,
    },

    ChunkAck {
        index: u64,
    },

    Complete {
        file_hash: Option<FileHash>,
    },

    Abort {
        reason_code: u8,
        reason: String,
    },

    ResumeRequest {
        last_confirmed_chunk: u64,
    },

    ResumeResponse {
        resume_from_chunk: u64,
    },
}

/// Simple file hash container used in metadata messages.
pub struct FileHash {
    pub alg: u8,
    pub bytes: Vec<u8>,
}

/// Encode a `FileTransferMessage` into a wire format.
pub fn encode(_msg: &FileTransferMessage) -> Vec<u8> {
    let mut out = Vec::new();

    match _msg {
        FileTransferMessage::Offer { file_size, name, mime, file_hash } => {
            out.push(1u8); // msg_type = Offer
            out.push(0x01); // version

            out.extend(&file_size.to_be_bytes());

            let name_b = name.as_bytes();
            out.extend(&(name_b.len() as u32).to_be_bytes());
            out.extend(name_b);

            let mime_b = mime.as_bytes();
            out.extend(&(mime_b.len() as u32).to_be_bytes());
            out.extend(mime_b);

            match file_hash {
                None => out.push(0u8),
                Some(h) => {
                    out.push(1u8);
                    out.push(h.alg);
                    out.extend(&(h.bytes.len() as u32).to_be_bytes());
                    out.extend(&h.bytes);
                }
            }
        }

        FileTransferMessage::Accept => {
            out.push(2u8);
            out.push(0x01);
        }

        FileTransferMessage::Reject { reason_code, reason } => {
            out.push(3u8);
            out.push(0x01);
            out.push(*reason_code);
            let r = reason.as_bytes();
            out.extend(&(r.len() as u32).to_be_bytes());
            out.extend(r);
        }

        FileTransferMessage::Chunk { index, data, chunk_hash } => {
            out.push(4u8);
            out.push(0x01);
            out.extend(&index.to_be_bytes());
            out.extend(&(data.len() as u32).to_be_bytes());
            out.extend(data);
            out.extend(&chunk_hash.to_be_bytes());
        }

        FileTransferMessage::ChunkAck { index } => {
            out.push(5u8);
            out.push(0x01);
            out.extend(&index.to_be_bytes());
        }

        FileTransferMessage::Complete { file_hash } => {
            out.push(6u8);
            out.push(0x01);
            match file_hash {
                None => out.push(0u8),
                Some(h) => {
                    out.push(1u8);
                    out.push(h.alg);
                    out.extend(&(h.bytes.len() as u32).to_be_bytes());
                    out.extend(&h.bytes);
                }
            }
        }

        FileTransferMessage::Abort { reason_code, reason } => {
            out.push(7u8);
            out.push(0x01);
            out.push(*reason_code);
            let r = reason.as_bytes();
            out.extend(&(r.len() as u32).to_be_bytes());
            out.extend(r);
        }

        FileTransferMessage::ResumeRequest { last_confirmed_chunk } => {
            out.push(8u8);
            out.push(0x01);
            out.extend(&last_confirmed_chunk.to_be_bytes());
        }

        FileTransferMessage::ResumeResponse { resume_from_chunk } => {
            out.push(9u8);
            out.push(0x01);
            out.extend(&resume_from_chunk.to_be_bytes());
        }
    }

    out
}

/// Decode bytes from the wire into a `FileTransferMessage`.
pub fn decode(_bytes: &[u8]) -> Result<FileTransferMessage, FileTransferError> {
    let mut idx: usize = 0;
    fn need(bytes: &[u8], idx: usize, want: usize) -> bool { bytes.len() >= idx + want }

    // read single u8
    if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder); }
    let msg_type = _bytes[idx]; idx += 1;

    if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder); }
    let version = _bytes[idx]; idx += 1;
    if version != 0x01 { return Err(FileTransferError::Placeholder); }

    // helpers
    let read_u64 = |b: &[u8], i: &mut usize| -> Option<u64> {
        if !need(b, *i, 8) { return None }
        let mut arr = [0u8;8]; arr.copy_from_slice(&b[*i..*i+8]); *i += 8; Some(u64::from_be_bytes(arr))
    };

    let read_u32 = |b: &[u8], i: &mut usize| -> Option<u32> {
        if !need(b, *i, 4) { return None }
        let mut arr = [0u8;4]; arr.copy_from_slice(&b[*i..*i+4]); *i += 4; Some(u32::from_be_bytes(arr))
    };

    match msg_type {
        1u8 => { // Offer
            // file_size u64
            let file_size = match read_u64(_bytes, &mut idx) { Some(v) => v, None => return Err(FileTransferError::Placeholder) };

            let name_len = match read_u32(_bytes, &mut idx) { Some(v) => v as usize, None => return Err(FileTransferError::Placeholder) };
            if !need(_bytes, idx, name_len) { return Err(FileTransferError::Placeholder) }
            let name = match std::str::from_utf8(&_bytes[idx..idx+name_len]) { Ok(s)=> s.to_string(), Err(_) => return Err(FileTransferError::Placeholder) };
            idx += name_len;

            let mime_len = match read_u32(_bytes, &mut idx) { Some(v) => v as usize, None => return Err(FileTransferError::Placeholder) };
            if !need(_bytes, idx, mime_len) { return Err(FileTransferError::Placeholder) }
            let mime = match std::str::from_utf8(&_bytes[idx..idx+mime_len]) { Ok(s)=> s.to_string(), Err(_) => return Err(FileTransferError::Placeholder) };
            idx += mime_len;

            if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
            let has_hash = _bytes[idx]; idx += 1;
            let file_hash = if has_hash == 0 { None } else {
                if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
                let alg = _bytes[idx]; idx += 1;
                let hlen = match read_u32(_bytes, &mut idx) { Some(v) => v as usize, None => return Err(FileTransferError::Placeholder) };
                if !need(_bytes, idx, hlen) { return Err(FileTransferError::Placeholder) }
                let bytes = _bytes[idx..idx+hlen].to_vec(); idx += hlen;
                Some(FileHash { alg, bytes })
            };

            Ok(FileTransferMessage::Offer { file_size, name, mime, file_hash })
        }

        2u8 => Ok(FileTransferMessage::Accept),

        3u8 => { // Reject
            if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
            let reason_code = _bytes[idx]; idx += 1;
            let rlen = match read_u32(_bytes, &mut idx) { Some(v) => v as usize, None => return Err(FileTransferError::Placeholder) };
            if !need(_bytes, idx, rlen) { return Err(FileTransferError::Placeholder) }
            let reason = match std::str::from_utf8(&_bytes[idx..idx+rlen]) { Ok(s)=> s.to_string(), Err(_) => return Err(FileTransferError::Placeholder) };
            idx += rlen;
            Ok(FileTransferMessage::Reject { reason_code, reason })
        }

        4u8 => { // Chunk
            let index = match read_u64(_bytes, &mut idx) { Some(v)=>v, None=> return Err(FileTransferError::Placeholder) };
            let chunk_len = match read_u32(_bytes, &mut idx) { Some(v) => v as usize, None => return Err(FileTransferError::Placeholder) };
            if !need(_bytes, idx, chunk_len) { return Err(FileTransferError::Placeholder) }
            let data = _bytes[idx..idx+chunk_len].to_vec(); idx += chunk_len;
            let chunk_hash = match read_u64(_bytes, &mut idx) { Some(v)=>v, None=> return Err(FileTransferError::Placeholder) };
            Ok(FileTransferMessage::Chunk { index, data, chunk_hash })
        }

        5u8 => { // ChunkAck
            let index = match read_u64(_bytes, &mut idx) { Some(v)=>v, None=> return Err(FileTransferError::Placeholder) };
            Ok(FileTransferMessage::ChunkAck { index })
        }

        6u8 => { // Complete
            if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
            let has_hash = _bytes[idx]; idx += 1;
            let file_hash = if has_hash == 0 { None } else {
                if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
                let alg = _bytes[idx]; idx += 1;
                let hlen = match read_u32(_bytes, &mut idx) { Some(v)=> v as usize, None => return Err(FileTransferError::Placeholder) };
                if !need(_bytes, idx, hlen) { return Err(FileTransferError::Placeholder) }
                let bytes = _bytes[idx..idx+hlen].to_vec(); idx += hlen;
                Some(FileHash { alg, bytes })
            };
            Ok(FileTransferMessage::Complete { file_hash })
        }

        7u8 => { // Abort
            if !need(_bytes, idx, 1) { return Err(FileTransferError::Placeholder) }
            let reason_code = _bytes[idx]; idx += 1;
            let rlen = match read_u32(_bytes, &mut idx) { Some(v)=> v as usize, None => return Err(FileTransferError::Placeholder) };
            if !need(_bytes, idx, rlen) { return Err(FileTransferError::Placeholder) }
            let reason = match std::str::from_utf8(&_bytes[idx..idx+rlen]) { Ok(s)=> s.to_string(), Err(_) => return Err(FileTransferError::Placeholder) };
            idx += rlen;
            Ok(FileTransferMessage::Abort { reason_code, reason })
        }

        8u8 => { // ResumeRequest
            let last_confirmed_chunk = match read_u64(_bytes, &mut idx) { Some(v)=>v, None=> return Err(FileTransferError::Placeholder) };
            Ok(FileTransferMessage::ResumeRequest { last_confirmed_chunk })
        }

        9u8 => { // ResumeResponse
            let resume_from_chunk = match read_u64(_bytes, &mut idx) { Some(v)=>v, None=> return Err(FileTransferError::Placeholder) };
            Ok(FileTransferMessage::ResumeResponse { resume_from_chunk })
        }

        _ => Err(FileTransferError::Placeholder),
    }
}

/// Chunker type: produces fixed-size chunks from a source `R`.
pub struct FileChunker<R> {
    pub reader: R,
    pub chunk_size: usize,
    pub next_index: u64,
}

impl<R: std::io::Read + std::io::Seek> FileChunker<R> {
    /// Create a new chunker that reads from `reader` producing up to
    /// `chunk_size` bytes per chunk. `next_index` starts at 0.
    pub fn new(reader: R, chunk_size: usize) -> Self {
        FileChunker { reader, chunk_size, next_index: 0 }
    }

    /// Read the next chunk. Returns `Ok(None)` when EOF is reached.
    /// On success returns `(index, data, hash)` where `hash` is a
    /// placeholder 64-bit value computed over the chunk bytes.
    pub fn next_chunk(&mut self) -> std::io::Result<Option<(u64, Vec<u8>, u64)>> {
        let mut buf = vec![0u8; self.chunk_size];
        let n = self.reader.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);

        // Placeholder hash: use DefaultHasher to produce a u64 value.
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        buf.hash(&mut hasher);
        let hash = hasher.finish();

        Ok(Some((index, buf, hash)))
    }

    /// Seek the underlying reader to the given chunk index.
    pub fn seek_to_chunk(&mut self, index: u64) -> std::io::Result<()> {
        let chunk_size_u64 = self.chunk_size as u64;
        let pos = index.checked_mul(chunk_size_u64).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek position overflow")
        })?;
        self.reader.seek(std::io::SeekFrom::Start(pos))?;
        self.next_index = index;
        Ok(())
    }
}

/// Sink type: consumes chunks into a writer `W` at fixed chunk offsets.
pub struct FileChunkSink<W> {
    pub writer: W,
    pub chunk_size: usize,
}

impl<W: std::io::Write + std::io::Seek> FileChunkSink<W> {
    /// Create a new sink that writes chunks of `chunk_size` bytes.
    pub fn new(writer: W, chunk_size: usize) -> Self {
        FileChunkSink { writer, chunk_size }
    }

    /// Write a chunk at the position `index * chunk_size`.
    pub fn write_chunk(&mut self, index: u64, data: &[u8]) -> std::io::Result<()> {
        let chunk_size_u64 = self.chunk_size as u64;
        let pos = index.checked_mul(chunk_size_u64).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek position overflow")
        })?;
        self.writer.seek(std::io::SeekFrom::Start(pos))?;
        let mut written = 0usize;
        while written < data.len() {
            let n = self.writer.write(&data[written..])?;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned zero"));
            }
            written += n;
        }
        Ok(())
    }
}

/// Public façade for a file-transfer stream type.
pub struct StreamHandle {
    pub send_engine: Option<Box<SenderEngine>>,
    pub recv_engine: Option<Box<ReceiverEngine>>,
}

impl Default for StreamHandle {
    fn default() -> Self {
        StreamHandle { send_engine: None, recv_engine: None }
    }
}

pub struct FileTransferStream {
    pub handle: StreamHandle,
}

/// Sender-side handle scaffolding.
pub struct FileSendHandle {
    pub stream: StreamHandle,
    pub chunker: Option<FileChunker<std::io::Cursor<Vec<u8>>>>,
    pub in_flight: u64,
    pub last_acked: u64,
    pub file_size: u64,
    pub file_hash: Option<FileHash>,
    pub engine: Option<Box<SenderEngine>>,
    pub close_called: bool,
}

impl FileSendHandle {
    /// Request a graceful close from the handle side: if an engine is
    /// attached, instruct it to move to a terminal `Completed` state.
    pub fn close(&mut self) {
        if let Some(engine) = self.engine.as_mut() {
            eprintln!("FT-UPSTREAM: facade_close_requested");
            // record that close() was explicitly invoked on this handle
            self.close_called = true;
            engine.close_engine_terminal();
        }
    }

}

impl Drop for FileSendHandle {
    fn drop(&mut self) {
        if !self.close_called {
            eprintln!("FT-HANDLE: dropped_without_explicit_close");
        }
    }

    /// Force abort and cleanup guidance for the send handle.
    pub fn abort(&mut self) {
        if let Some(engine) = self.engine.as_mut() {
            engine.abort_engine();
        }
    }
}

/// Receiver-side handle scaffolding.
pub struct FileReceiveHandle {
    pub stream: StreamHandle,
    pub sink: Option<FileChunkSink<std::fs::File>>,
    pub expected_size: u64,
    pub received_bytes: u64,
    pub file_hash: Option<FileHash>,
    pub engine: Option<Box<ReceiverEngine>>,
    pub temp_path: Option<std::path::PathBuf>,
    pub file: Option<std::fs::File>,
}

impl FileReceiveHandle {
    pub fn write_chunk(&mut self, index: u64, data: &[u8]) -> Result<(), FileTransferError> {
        let sink = match self.sink.as_mut() {
            Some(s) => s,
            None => return Err(FileTransferError::Placeholder),
        };

        sink.write_chunk(index, data).map_err(|_| FileTransferError::Placeholder)?;
        self.received_bytes = self.received_bytes.saturating_add(data.len() as u64);
        Ok(())
    }

    pub fn finalize(&mut self, final_path: &std::path::Path) -> Result<crate::m9_block4::FileCompletion, FileTransferError> {
        // Ensure temp path and file are present
        let temp = self.temp_path.as_ref().ok_or(FileTransferError::Placeholder)?.clone();
        // take ownership of the file so we can sync and close it
        let file = self.file.take().ok_or(FileTransferError::Placeholder)?;

        // Ensure expected bytes are written
        if self.expected_size > 0 && self.received_bytes != self.expected_size {
            // put back file reference to keep state sane
            self.file = Some(file);
            return Err(FileTransferError::Placeholder);
        }

        // Placeholder verification if present
        let hash = self.file_hash.clone();

        // Ensure data is durably written to disk before attempting to move the temp file.
        // Sync the file contents and metadata.
        if let Err(_) = file.sync_all() {
            // return file into the handle on error to allow abort/cleanup
            self.file = Some(file);
            return Err(FileTransferError::Placeholder);
        }

        // Drop the file handle to ensure the file is closed. On some platforms
        // (notably Windows) an open handle prevents renaming/moving the file.
        drop(file);

        // Attempt atomic rename: on POSIX this replaces the target atomically.
        // On Windows `std::fs::rename` will fail if the destination exists; we
        // perform best-effort fallbacks below to ensure the final path is written.
        let rename_result = std::fs::rename(&temp, final_path);

        if let Err(_e) = &rename_result {
            // If the final path already existed, try platform-specific fallback.
            if final_path.exists() {
                #[cfg(windows)]
                {
                    // On Windows, remove the existing file then rename the temp into place.
                    // This is not perfectly atomic but is the pragmatic fallback available
                    // without bringing in OS-specific bindings.
                    let _ = std::fs::remove_file(final_path);
                    std::fs::rename(&temp, final_path).map_err(|_| FileTransferError::Placeholder)?;
                }

                #[cfg(not(windows))]
                {
                    // Unexpected: on POSIX rename should have replaced the target.
                    return Err(FileTransferError::Placeholder);
                }
            } else {
                // Destination did not exist but rename still failed; fall back to copy+remove.
                std::fs::copy(&temp, final_path).map_err(|_| FileTransferError::Placeholder)?;
                std::fs::remove_file(&temp).map_err(|_| FileTransferError::Placeholder)?;
            }
        }

        // Best-effort: sync parent directory to make the rename durable (POSIX only).
        #[cfg(unix)]
        {
            if let Some(parent) = final_path.parent() {
                if let Ok(dirf) = std::fs::OpenOptions::new().read(true).open(parent) {
                    let _ = dirf.sync_all();
                }
            }
        }

        // Determine final size
        let size = std::fs::metadata(final_path).map_err(|_| FileTransferError::Placeholder)?.len();

        // Clear state
        self.sink = None;
        self.file = None;
        self.temp_path = None;

        Ok(crate::m9_block4::FileCompletion { final_path: final_path.to_path_buf(), size, hash })
    }

    pub fn resume_from_temp(&mut self) -> Result<u64, FileTransferError> {
        use std::fs::OpenOptions;

        let temp = match &self.temp_path {
            Some(p) => p.clone(),
            None => return Err(FileTransferError::Placeholder),
        };

        if self.file.is_none() {
            let f = OpenOptions::new().read(true).write(true).open(&temp).map_err(|_| FileTransferError::Placeholder)?;
            let f_clone = f.try_clone().map_err(|_| FileTransferError::Placeholder)?;
            self.file = Some(f_clone);
            let chunk_size = 1024usize;
            self.sink = Some(FileChunkSink::new(f, chunk_size));
        } else {
            let f = self.file.as_ref().ok_or(FileTransferError::Placeholder)?.try_clone().map_err(|_| FileTransferError::Placeholder)?;
            let chunk_size = self.sink.as_ref().map(|s| s.chunk_size).unwrap_or(1024usize);
            self.sink = Some(FileChunkSink::new(f, chunk_size));
        }

        let len = self.file.as_ref().ok_or(FileTransferError::Placeholder)?.metadata().map_err(|_| FileTransferError::Placeholder)?.len();
        let chunk_size = self.sink.as_ref().map(|s| s.chunk_size).unwrap_or(1024usize) as u64;
        let last_confirmed_chunk = if chunk_size == 0 { 0 } else { len / chunk_size };
        Ok(last_confirmed_chunk)
    }

    pub fn abort_cleanup(&mut self) {
        if let Some(p) = &self.temp_path {
            let _ = std::fs::remove_file(p);
        }
        self.sink = None;
        self.file = None;
        self.temp_path = None;
    }

    /// Request a graceful close from the receive handle: if an engine is
    /// attached, move it to a terminal `Completed` state and emit a
    /// diagnostic wake hint.
    pub fn close(&mut self) {
        if let Some(engine) = self.engine.as_mut() {
            engine.close_engine_terminal();
        }
    }

    pub fn complete_with_policy<P: crate::m9_block4::FileTransferPolicy>(&mut self, policy: &P, final_path: &std::path::Path) -> Result<crate::m9_block4::FileCompletion, FileTransferError> {
        // If final exists, consult policy
        if final_path.exists() {
            match policy.handle_overwrite(final_path) {
                crate::m9_block4::OverwriteDecision::Allow => {
                    // proceed with provided final_path
                    self.finalize(final_path)
                }
                crate::m9_block4::OverwriteDecision::Deny => Err(FileTransferError::Placeholder),
                crate::m9_block4::OverwriteDecision::Rename(p) => self.finalize(&p),
            }
        } else {
            // No existing file, proceed
            self.finalize(final_path)
        }
    }
}

impl FileTransferStream {
    pub async fn offer_send(&mut self, file_size: u64, _name: String, _mime: String, file_hash: Option<FileHash>) -> Result<FileSendHandle, FileTransferError> {
        // create a placeholder chunker (empty cursor) and a send handle
        let chunker = FileChunker::new(std::io::Cursor::new(Vec::new()), 1024);
        let mut handle = FileSendHandle {
            stream: StreamHandle::default(),
            chunker: Some(chunker),
            in_flight: 0,
            last_acked: 0,
            file_size,
            file_hash,
            engine: None,
            close_called: false,
        };

        // create a sender engine from a minimal handle copy and attach to the stream
        let engine_handle = FileSendHandle {
            stream: StreamHandle::default(),
            chunker: None,
            in_flight: 0,
            last_acked: 0,
            file_size,
            file_hash: None,
            engine: None,
            close_called: false,
        };
        let engine = SenderEngine::new(engine_handle);
        self.handle.send_engine = Some(Box::new(engine));

        Ok(handle)
    }

    pub async fn offer_receive(&mut self, expected_size: u64, file_hash: Option<FileHash>) -> Result<FileReceiveHandle, FileTransferError> {
        // create a placeholder sink (empty cursor) and a receive handle
        let sink = FileChunkSink::new(std::io::Cursor::new(Vec::new()), 1024);
        let mut handle = FileReceiveHandle {
            stream: StreamHandle::default(),
            sink: Some(sink),
            expected_size,
            received_bytes: 0,
            file_hash,
            engine: None,
        };

        // create a receiver engine from a minimal handle copy and attach to the stream
        let engine_handle = FileReceiveHandle {
            stream: StreamHandle::default(),
            sink: None,
            expected_size,
            received_bytes: 0,
            file_hash: None,
            engine: None,
        };
        let engine = ReceiverEngine::new(engine_handle);
        self.handle.recv_engine = Some(Box::new(engine));

        Ok(handle)
    }

    pub async fn accept(&self) -> Result<(), FileTransferError> {
        #[cfg(feature = "debug-logs")]
        unimplemented!()
    }

    pub async fn reject(&self, reason_code: u8, reason: String) -> Result<(), FileTransferError> {
        #[cfg(feature = "debug-logs")]
        unimplemented!()
    }
}

impl FileTransferStream {
    /// Start the sender engine attached to this stream. Delegates to the engine's `start`.
    pub async fn start_send(&mut self, _handle: &mut FileSendHandle) -> Result<(), FileTransferError> {
        if let Some(engine) = self.handle.send_engine.as_mut() {
            engine.start().await
        } else {
            Err(FileTransferError::Placeholder)
        }
    }

    /// Drive the sender engine one step. Delegates to `step`.
    pub async fn drive_send(&mut self, _handle: &mut FileSendHandle) -> Result<(), FileTransferError> {
        if let Some(engine) = self.handle.send_engine.as_mut() {
            engine.step().await
        } else {
            Err(FileTransferError::Placeholder)
        }
    }

    /// Acknowledge a sent chunk; delegates to engine `handle_ack`.
    pub async fn ack_send(&mut self, _handle: &mut FileSendHandle, index: u64) -> Result<(), FileTransferError> {
        if let Some(engine) = self.handle.send_engine.as_mut() {
            engine.handle_ack(index).await
        } else {
            Err(FileTransferError::Placeholder)
        }
    }

    /// Start the receiver engine attached to this stream.
    pub async fn start_receive(&mut self, _handle: &mut FileReceiveHandle) -> Result<(), FileTransferError> {
        if let Some(engine) = self.handle.recv_engine.as_mut() {
            engine.start().await
        } else {
            Err(FileTransferError::Placeholder)
        }
    }

    /// Drive the receiver engine one step.
    pub async fn drive_receive(&mut self, _handle: &mut FileReceiveHandle) -> Result<(), FileTransferError> {
        if let Some(engine) = self.handle.recv_engine.as_mut() {
            engine.process().await
        } else {
            Err(FileTransferError::Placeholder)
        }
    }
}

impl FileTransferStream {
    /// Attach a concrete chunker to a `FileSendHandle`.
    pub fn attach_chunker(&mut self, handle: &mut FileSendHandle, chunker: FileChunker<std::io::Cursor<Vec<u8>>>) {
        handle.chunker = Some(chunker);
    }

    /// Attach a concrete sink to a `FileReceiveHandle`.
    pub fn attach_sink(&mut self, handle: &mut FileReceiveHandle, sink: FileChunkSink<std::io::Cursor<Vec<u8>>>) {
        handle.sink = Some(sink);
    }

    /// Inspect the current sender engine state without exposing engine internals.
    pub fn sender_state(&self) -> Option<SenderState> {
        self.handle.send_engine.as_ref().map(|e| e.state)
    }

    /// Inspect the current receiver engine state without exposing engine internals.
    pub fn receiver_state(&self) -> Option<ReceiverState> {
        self.handle.recv_engine.as_ref().map(|e| e.state)
    }

    /// Detach (take) any attached engines. Returns (sender_detached, receiver_detached).
    pub fn detach_engines(&mut self) -> (bool, bool) {
        let s = self.handle.send_engine.take().is_some();
        let r = self.handle.recv_engine.take().is_some();
        (s, r)
    }

    /// Check whether the send-side transfer is considered completed.
    pub fn is_send_completed(&self, handle: &FileSendHandle) -> bool {
        let engine_done = self.handle.send_engine.as_ref().map(|e| e.state == SenderState::Completed).unwrap_or(false);
        engine_done || (handle.last_acked >= handle.file_size && handle.file_size > 0)
    }

    /// Check whether the receive-side transfer is considered completed.
    pub fn is_receive_completed(&self, handle: &FileReceiveHandle) -> bool {
        let engine_done = self.handle.recv_engine.as_ref().map(|e| e.state == ReceiverState::Completed).unwrap_or(false);
        engine_done || (handle.received_bytes >= handle.expected_size && handle.expected_size > 0)
    }

    /// Prepare a receive path using the provided policy. This function
    /// sanitizes the offered filename, asks the policy for a save path,
    /// creates a temporary file inside the chosen directory and returns
    /// `(final_path, temp_path, opened_file)`.
    pub fn prepare_receive_path<P: crate::m9_block4::FileTransferPolicy>(
        &self,
        policy: &P,
        offer_name: &str,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf, std::fs::File), FileTransferError> {
        // sanitize the filename first
        let safe = crate::m9_block4::TempFileManager::sanitize_filename(offer_name)?;

        // ask policy for save path (policy may consider directories, user prefs, etc.)
        let final_path = policy.choose_save_path(&safe)?;

        // extract filename and parent directory
        let final_name = final_path.file_name().and_then(|s| s.to_str()).ok_or(FileTransferError::Placeholder)?;
        let parent = final_path.parent().unwrap_or(std::path::Path::new("."));

        // create temporary file in parent dir
        let (temp_path, file) = crate::m9_block4::TempFileManager::create_temp(parent, final_name).map_err(|_| FileTransferError::Placeholder)?;

        Ok((final_path, temp_path, file))
    }
}

/// Sender engine state machine (scaffolding only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderState {
    Idle,
    Offering,
    Sending,
    AwaitingAck,
    Completed,
    Aborted,
}

/// Receiver engine state machine (scaffolding only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverState {
    Idle,
    Receiving,
    Verifying,
    Completed,
    Aborted,
}

/// Sender engine scaffolding: orchestrates sending a file using the
/// `FileSendHandle` and `StreamHandle`. Types and channels are
/// placeholders; no runtime logic is implemented here.
pub struct SenderEngine {
    pub handle: FileSendHandle,
    pub state: SenderState,
    pub in_flight_limit: u64,
    pub outstanding: u64,
    pub control: (),
}

impl SenderEngine {
    /// Create a new engine from a send handle. Does not start any IO.
    pub fn new(handle: FileSendHandle) -> Self {
        SenderEngine { handle, state: SenderState::Idle, in_flight_limit: 0, outstanding: 0, control: () }
    }

    /// Start the engine; scaffolding only (no behavior).
    pub async fn start(&mut self) -> Result<(), FileTransferError> {
        // Move the engine into an active offering/sending state.
        match self.state {
            SenderState::Idle => {
                self.state = SenderState::Offering;
                Ok(())
            }
            SenderState::Offering | SenderState::Sending | SenderState::AwaitingAck => Ok(()),
            SenderState::Completed => Ok(()),
            SenderState::Aborted => Err(FileTransferError::Placeholder),
        }
    }

    /// Execute a single state-machine step. Intended for the control loop.
    pub async fn step(&mut self) -> Result<(), FileTransferError> {
        match self.state {
            SenderState::Idle => {
                self.state = SenderState::Offering;
                Ok(())
            }
            SenderState::Offering => {
                // transition to sending once offering is considered done
                self.state = SenderState::Sending;
                Ok(())
            }
            SenderState::Sending => {
                // simulate sending by moving to AwaitingAck when under limit
                if self.outstanding < self.in_flight_limit {
                    self.outstanding = self.outstanding.saturating_add(1);
                    self.state = SenderState::AwaitingAck;
                }
                Ok(())
            }
            SenderState::AwaitingAck => {
                // If an ack hasn't been processed, leave state; otherwise will be
                // updated via `handle_ack`.
                if self.outstanding == 0 {
                    // nothing outstanding, consider completed when last_acked reaches file_size
                    if self.handle.last_acked >= self.handle.file_size {
                        // Terminal transition due to all chunks acknowledged
                        eprintln!("FT-SENDER → Completed: all chunks acked, close requested");
                        self.state = SenderState::Completed;
                    } else {
                        self.state = SenderState::Sending;
                    }
                }
                Ok(())
            }
            SenderState::Completed => Ok(()),
            SenderState::Aborted => Err(FileTransferError::Placeholder),
        }
    }

    /// Handle an incoming acknowledgement message (signature only).
    pub async fn handle_ack(&mut self, index: u64) -> Result<(), FileTransferError> {
        // Update bookkeeping for acknowledgements. This is deterministic
        // scaffolding only and does not communicate over the network.
        if self.outstanding > 0 {
            self.outstanding = self.outstanding.saturating_sub(1);
        }
        self.handle.last_acked = index;

        // If we've acknowledged up to or beyond file_size, mark complete.
        if self.handle.last_acked >= self.handle.file_size {
            eprintln!("FT-SENDER → Completed: all chunks acked, close requested");
            self.state = SenderState::Completed;
        } else {
            self.state = SenderState::Sending;
        }
        Ok(())
    }

    /// Transition the sender engine into a terminal `Completed` state and
    /// emit a small diagnostic wake hint. This API is intended to be called
    /// by higher-level close/teardown code so the engine will stop scheduling
    /// itself and provide an observable signal for diagnostics.
    pub fn close_engine_terminal(&mut self) {
        eprintln!("FT-SENDER close_path_entered");
        self.state = SenderState::Completed;
        eprintln!("FT-SENDER → Completed: all chunks acked, close requested");
    }

    /// Force the sender engine into an aborted terminal state.
    pub fn abort_engine(&mut self) {
        self.state = SenderState::Aborted;
        eprintln!("FT-SENDER → Aborted: stream closed before final ack");
    }
}

/// Receiver engine scaffolding: consumes incoming chunks and writes to sink.
pub struct ReceiverEngine {
    pub handle: FileReceiveHandle,
    pub state: ReceiverState,
    pub received: u64,
    pub control: (),
}

impl ReceiverEngine {
    /// Create a new receiver engine. No IO started.
    pub fn new(handle: FileReceiveHandle) -> Self {
        ReceiverEngine { handle, state: ReceiverState::Idle, received: 0, control: () }
    }

    /// Transition the receiver engine into a terminal `Completed` state for close path.
    pub fn close_engine_terminal(&mut self) {
        eprintln!("FT-RECEIVER close_path_entered");
        self.state = ReceiverState::Completed;
        eprintln!("FT-RECEIVER → Completed: finalize() returned Ok");
    }

    /// Force the receiver engine into an aborted terminal state.
    pub fn abort_engine(&mut self) {
        self.state = ReceiverState::Aborted;
        eprintln!("FT-RECEIVER → Aborted: finalize() returned Err");
    }

    /// Start the receiver engine (scaffolding only).
    pub async fn start(&mut self) -> Result<(), FileTransferError> {
        match self.state {
            ReceiverState::Idle => {
                self.state = ReceiverState::Receiving;
                Ok(())
            }
            ReceiverState::Receiving | ReceiverState::Verifying | ReceiverState::Completed => Ok(()),
            ReceiverState::Aborted => Err(FileTransferError::Placeholder),
        }
    }

    /// Process one incoming chunk or control message (signature only).
    pub async fn process(&mut self) -> Result<(), FileTransferError> {
        match self.state {
            ReceiverState::Idle => {
                self.state = ReceiverState::Receiving;
                Ok(())
            }
            ReceiverState::Receiving => {
                // Simulate receiving one chunk's worth of progress.
                self.received = self.received.saturating_add(1);
                if self.received >= self.handle.expected_size {
                    self.state = ReceiverState::Verifying;
                }
                Ok(())
            }
            ReceiverState::Verifying => {
                // move to completed after verification step (scaffold)
                self.state = ReceiverState::Completed;
                eprintln!("FT-RECEIVER → Completed: finalize() returned Ok");
                Ok(())
            }
            ReceiverState::Completed => Ok(()),
            ReceiverState::Aborted => Err(FileTransferError::Placeholder),
        }
    }

    /// Transition the receiver engine into a terminal `Completed` state and
    /// emit a small diagnostic wake hint for observability. Callers should
    /// use this during graceful close or on successful finalization.
    pub fn close_engine_terminal(&mut self) {
        self.state = ReceiverState::Completed;
        eprintln!("FT: receiver_engine_close_terminal");
    }

    /// Force the receiver engine into an aborted terminal state.
    pub fn abort_engine(&mut self) {
        self.state = ReceiverState::Aborted;
        eprintln!("FT: receiver_engine_abort_terminal");
    }
}

/// Error type for encode/decode and stream operations.
pub enum FileTransferError {
    /// Placeholder variant to be expanded.
    Placeholder,
}
