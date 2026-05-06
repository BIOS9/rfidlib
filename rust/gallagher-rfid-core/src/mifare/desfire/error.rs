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
}
