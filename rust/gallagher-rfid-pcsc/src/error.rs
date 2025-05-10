use std::fmt::Debug;
use std::fmt;

#[derive(Debug)]
pub enum SmartCardError {
    ContextInitFailed(String),
    ReaderListFailed(String),
    CardConnectFailed(String),
    CardCommunicateFailed(String),
    UnsupportedReader(String),
}

impl fmt::Display for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmartCardError::ContextInitFailed(msg) => write!(f, "Context initialization failed: {}", msg),
            SmartCardError::ReaderListFailed(msg) => write!(f, "Reader list failed: {}", msg),
            SmartCardError::CardConnectFailed(msg) => write!(f, "Card connect failed: {}", msg),
            SmartCardError::CardCommunicateFailed(msg) => write!(f, "Communication with card failed: {}", msg),
            SmartCardError::UnsupportedReader(msg) => write!(f, "The selected reader is not supported: {}", msg),
        }
    }
}

impl std::error::Error for SmartCardError {}