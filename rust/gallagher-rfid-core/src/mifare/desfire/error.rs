use crate::mifare::desfire::status::Status;

/// Errors raised by core `DESFire` command handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A command payload is too large for the selected frame representation.
    CommandTooLong,
    /// A response frame was empty or otherwise malformed.
    MalformedResponse,
    /// A wrapped APDU response did not contain the `DESFire` status marker.
    InvalidWrappedResponse,
    /// The caller-provided response buffer was too small for the card data.
    ResponseTooLong,
    /// The card returned too many continuation frames for one command.
    TooManyAdditionalFrames,
    /// A successful response did not have the expected shape for the command.
    InvalidResponseLength,
    /// AES authentication failed because the card did not prove knowledge of the key.
    AuthenticationFailed,
    /// A secure-messaging command requires prior authentication.
    MissingAuthentication,
    /// A response MAC did not match the active authenticated session.
    InvalidMac,
    /// An encrypted response CRC did not match the decrypted payload.
    InvalidCrc,
    /// An encrypted response did not contain valid zero padding.
    InvalidPadding,
    /// The card returned a non-success `DESFire` status.
    Status(Status),
    /// An application identifier exceeded the `DESFire` 24-bit AID range.
    InvalidApplicationId(u32),
    /// A file identifier exceeded the `DESFire` file-id range.
    InvalidFileId(u8),
    /// A key number exceeded the `DESFire` key-number range.
    InvalidKeyNumber(u8),
    /// A file communication-mode byte was not recognized.
    InvalidCommunicationMode(u8),
    /// A file-type byte was not recognized.
    InvalidFileType(u8),
    /// The transport layer failed to exchange a frame with the tag.
    Transport,
    /// The operation requires a cryptographic algorithm that is not yet implemented.
    UnsupportedAlgorithm,
}
