use std::fmt;
use std::fmt::Debug;

use gallagher_rfid_core::mifare;

#[derive(Debug)]
pub enum Error {
    ContextInitFailed(String),
    ReaderListFailed(String),
    CardConnectFailed(String),
    CardCommunicateFailed(String),
    UnsupportedReader(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ContextInitFailed(msg) => {
                write!(f, "Context initialization failed: {}", msg)
            }
            Error::ReaderListFailed(msg) => write!(f, "Reader list failed: {}", msg),
            Error::CardConnectFailed(msg) => write!(f, "Card connect failed: {}", msg),
            Error::CardCommunicateFailed(msg) => {
                write!(f, "Communication with card failed: {}", msg)
            }
            Error::UnsupportedReader(msg) => {
                write!(f, "The selected reader is not supported: {}", msg)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for mifare::classic::Error {
    fn from(err: Error) -> Self {
        mifare::classic::Error::TransportError(err.to_string())
    }
}
