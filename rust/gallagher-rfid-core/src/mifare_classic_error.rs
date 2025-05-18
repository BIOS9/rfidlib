use std::string::String;

#[derive(Debug)]
pub enum MifareClassicError {
    /// Failed to authenticate to a block.
    AuthenticationFailed {
        block: u8,
        reason: String,
    },

    /// Attempted to read or write an invalid block number.
    InvalidBlock(u8),

     /// Attempted to read or write an invalid sector number.
    InvalidSector(u8),

    /// Data returned from card is the wrong length.
    InvalidDataLength {
        expected: usize,
        received: usize,
    },

    /// Low-level PCSC or transport error.
    TransportError(String),
}