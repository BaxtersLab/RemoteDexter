pub mod state;
pub mod events;
pub mod commands;
pub mod engine;
pub mod errors;
pub mod codec;
pub mod frame;
pub mod media;

pub use state::APKSessionState;
pub use events::{APKSessionEvent, NegotiationResponse};
pub use commands::{APKSessionCommand, APKSessionConfig, NegotiationRequest};
pub use engine::APKSessionEngine;
pub use errors::APKSessionError;
pub use codec::{encode_negotiation_request, decode_negotiation_response};
pub use engine::MAX_FRAMES;
pub use frame::FrameEnvelope;
// `decoder_hook::on_new_frame` was a no-op placeholder called on every queued
// frame. The real path is now queue -> tick -> JNI -> Kotlin BitmapFactory
// (see `rust/src/lib.rs::tick_and_dispatch_frame`), so the placeholder was
// removed rather than left sitting misleadingly in the live frame path.
pub use media::{MediaStreamKind, MediaControl, MediaFrame};

use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref ENGINE: Mutex<APKSessionEngine> = Mutex::new(APKSessionEngine::new());
}

#[no_mangle]
pub extern "C" fn rd_on_system_sleep() {
    let mut engine = ENGINE.lock().unwrap();
    engine.handle_event(APKSessionEvent::SystemSleep);
}

#[no_mangle]
pub extern "C" fn rd_on_system_wake() {
    let mut engine = ENGINE.lock().unwrap();
    engine.handle_event(APKSessionEvent::SystemWake);
}

#[no_mangle]
pub extern "C" fn rd_on_transport_idle() {
    let mut engine = ENGINE.lock().unwrap();
    engine.handle_event(APKSessionEvent::TransportIdle);
}

#[no_mangle]
pub extern "C" fn rd_on_transport_wake() {
    let mut engine = ENGINE.lock().unwrap();
    engine.handle_event(APKSessionEvent::TransportWake);
}

/// Camera frames from a caller outside Rust.
///
/// Behind `media_ingest`, which is off by default. See this crate's Cargo.toml
/// for why: RemoteDexter ships no camera or microphone capture and must not
/// export an ABI that ingests it.
#[cfg(feature = "media_ingest")]
#[no_mangle]
pub extern "C" fn rd_on_camera_frame(ptr: *const u8, len: usize, timestamp_ns: u64) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let data = slice.to_vec();
    let mut engine = ENGINE.lock().unwrap();
    engine.on_camera_frame_captured(data, timestamp_ns);
}

/// Microphone frames from a caller outside Rust.
///
/// Behind `media_ingest`, which is off by default — see `rd_on_camera_frame`.
#[cfg(feature = "media_ingest")]
#[no_mangle]
pub extern "C" fn rd_on_mic_frame(ptr: *const u8, len: usize, timestamp_ns: u64) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let data = slice.to_vec();
    let mut engine = ENGINE.lock().unwrap();
    engine.on_mic_frame_captured(data, timestamp_ns);
}