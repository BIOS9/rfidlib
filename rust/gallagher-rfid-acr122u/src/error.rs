use std::fmt::Debug;
use std::fmt;

#[derive(Debug)]
pub enum SmartCardError {
    ContextInitFailed(String),
    ReaderListFailed(String),
}

impl fmt::Display for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmartCardError::ContextInitFailed(msg) => write!(f, "Context initialization failed: {}", msg),
            SmartCardError::ReaderListFailed(msg) => write!(f, "Reader list failed: {}", msg),
        }
    }
}

impl std::error::Error for SmartCardError {}