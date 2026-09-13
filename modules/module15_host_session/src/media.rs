use std::sync::{Arc, Mutex};
use rodio::{OutputStream, Sink};

#[derive(Debug, Clone)]
pub enum MediaStreamKind {
    Camera,
    Microphone,
}

#[derive(Debug, Clone)]
pub struct MediaFrame {
    pub kind: MediaStreamKind,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CameraFrame {
    pub width: u32,
    pub height: u32,
    pub timestamp: u64,
    pub pixels: Vec<u8>, // RGBA
}

#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub timestamp: u64,
    pub samples: Vec<i16>,
}

pub struct MediaPreviewSink {
    pub on_camera_frame: Arc<Mutex<Option<Box<dyn Fn(CameraFrame) + Send + Sync>>>>,
    pub on_audio_frame: Arc<Mutex<Option<Box<dyn Fn(AudioFrame) + Send + Sync>>>>,
}

impl MediaPreviewSink {
    pub fn new() -> Self {
        Self {
            on_camera_frame: Arc::new(Mutex::new(None)),
            on_audio_frame: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_camera_callback<F>(&self, callback: F)
    where
        F: Fn(CameraFrame) + Send + Sync + 'static,
    {
        *self.on_camera_frame.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_audio_callback<F>(&self, callback: F)
    where
        F: Fn(AudioFrame) + Send + Sync + 'static,
    {
        *self.on_audio_frame.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn on_camera_frame_decoded(&self, frame: CameraFrame) {
        if let Some(ref callback) = *self.on_camera_frame.lock().unwrap() {
            callback(frame);
        }
    }

    pub fn on_audio_frame_decoded(&self, frame: AudioFrame) {
        if let Some(ref callback) = *self.on_audio_frame.lock().unwrap() {
            callback(frame);
        }
    }
}

pub struct AudioPlayer {
    _stream: OutputStream,
    sink: Sink,
    sample_rate: u32,
}

impl AudioPlayer {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (_stream, stream_handle) = OutputStream::try_default()?;
        let sink = Sink::try_new(&stream_handle)?;
        Ok(Self {
            _stream,
            sink,
            sample_rate: 16000, // 16kHz
        })
    }

    pub fn push_frame(&self, frame: AudioFrame) {
        // Convert i16 samples to f32
        let samples_f32: Vec<f32> = frame.samples.iter().map(|&s| s as f32 / 32768.0).collect();
        let source = rodio::buffer::SamplesBuffer::new(1, self.sample_rate, samples_f32);
        self.sink.append(source);
    }
}

pub trait VideoSurface: Send {
    fn present(&mut self, frame: &CameraFrame);
}

// Stub implementation
pub struct StubVideoSurface;

impl StubVideoSurface {
    pub fn new() -> Self {
        Self
    }
}

impl VideoSurface for StubVideoSurface {
    fn present(&mut self, frame: &CameraFrame) {
        // Stub: just log dimensions
        println!("Presenting video frame: {}x{}", frame.width, frame.height);
    }
}

pub fn decode_camera_frame(payload: &[u8], timestamp: u64) -> Option<CameraFrame> {
    // Assume JPEG for now
    match image::load_from_memory(payload) {
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (width, height) = rgba.dimensions();
            Some(CameraFrame {
                width,
                height,
                timestamp,
                pixels: rgba.into_raw(),
            })
        }
        Err(_) => None, // drop on decode failure
    }
}

pub fn decode_audio_frame(payload: &[u8], timestamp: u64) -> AudioFrame {
    // Assume 16-bit PCM mono
    let samples: Vec<i16> = payload
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    AudioFrame { timestamp, samples }
}