#[derive(Debug)]
pub enum RfidError {
    /// Transport layer failed (USB, NFC, I2C, etc.)
    Transport,

    /// No response from the card (timeout, bad antenna, etc.)
    Timeout,

    /// Response was invalid or unexpected (wrong length, wrong CRC, etc.)
    InvalidResponse,

    /// The response buffer was too small to hold the data
    BufferTooSmall,

    /// A protocol-level error (invalid APDU, unsupported command, etc.)
    Protocol,

    /// A generic error for things that don't fit the above
    Other,

    /// Optional: wrap other error types when using `std`
    #[cfg(feature = "std")]
    Io(std::io::Error),
}
