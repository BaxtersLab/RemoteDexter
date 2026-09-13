#[derive(Debug, Clone)]
pub enum MediaStreamKind {
    Camera,
    Microphone,
}

#[derive(Debug)]
pub enum MediaControl {
    Start(MediaStreamKind),
    Stop(MediaStreamKind),
}

#[derive(Debug)]
pub struct MediaFrame {
    pub kind: MediaStreamKind,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}