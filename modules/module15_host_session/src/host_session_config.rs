#[derive(Debug, Clone)]
pub struct HostSessionConfig {
    pub width: u32,
    pub height: u32,
    pub pixel_format: String,
    pub max_fps: u32,
}