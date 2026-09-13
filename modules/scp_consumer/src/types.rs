use connection_package_generator::ConnectionPackage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScpMessage {
    pub pkg: ConnectionPackage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScpError {
    InvalidInput,
    InvalidPackage,
}

impl From<connection_package_generator::ConnectionError> for ScpError {
    fn from(_e: connection_package_generator::ConnectionError) -> Self {
        ScpError::InvalidPackage
    }
}
