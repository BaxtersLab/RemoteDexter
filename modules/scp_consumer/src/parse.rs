use crate::types::{ScpMessage, ScpError};

pub fn parse_scp(raw: &[u8]) -> Result<ScpMessage, ScpError> {
    // For now Module 3's parser delegates to connection_package_generator's parser
    match connection_package_generator::parse_connection_package(raw) {
        Ok(pkg) => Ok(ScpMessage { pkg }),
        Err(e) => Err(ScpError::from(e)),
    }
}
