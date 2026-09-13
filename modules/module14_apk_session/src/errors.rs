#[derive(thiserror::Error, Debug)]
pub enum APKSessionError {
    #[error("transport error: {0}")]
    Transport(String),
}