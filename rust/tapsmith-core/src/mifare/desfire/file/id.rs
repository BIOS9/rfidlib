use crate::mifare::desfire::error::Error;

/// `DESFire` file identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(u8);

impl FileId {
    /// `DESFire` file ids are five bits in the common command encoding.
    pub const MAX: u8 = 0x1F;

    /// Creates a validated file id.
    pub fn new(value: u8) -> Result<Self, Error> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(Error::InvalidFileId(value))
        }
    }

    /// Raw file id byte.
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

impl From<FileId> for u8 {
    fn from(value: FileId) -> Self {
        value.0
    }
}
