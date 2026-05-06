use crate::mifare::desfire::{error::Error, file::AccessRights};

/// `DESFire` file communication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunicationMode {
    Plain,
    Maced,
    Enciphered,
}

impl TryFrom<u8> for CommunicationMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Plain),
            0x01 => Ok(Self::Maced),
            0x03 => Ok(Self::Enciphered),
            _ => Err(Error::InvalidCommunicationMode(value)),
        }
    }
}

impl From<CommunicationMode> for u8 {
    fn from(value: CommunicationMode) -> Self {
        match value {
            CommunicationMode::Plain => 0x00,
            CommunicationMode::Maced => 0x01,
            CommunicationMode::Enciphered => 0x03,
        }
    }
}

/// `DESFire` file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    StandardData,
    BackupData,
    Value,
    LinearRecord,
    CyclicRecord,
}

impl TryFrom<u8> for FileType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::StandardData),
            0x01 => Ok(Self::BackupData),
            0x02 => Ok(Self::Value),
            0x03 => Ok(Self::LinearRecord),
            0x04 => Ok(Self::CyclicRecord),
            _ => Err(Error::InvalidFileType(value)),
        }
    }
}

impl From<FileType> for u8 {
    fn from(value: FileType) -> Self {
        match value {
            FileType::StandardData => 0x00,
            FileType::BackupData => 0x01,
            FileType::Value => 0x02,
            FileType::LinearRecord => 0x03,
            FileType::CyclicRecord => 0x04,
        }
    }
}

/// Common settings shared by `DESFire` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSettings {
    file_type: FileType,
    communication_mode: CommunicationMode,
    access_rights: AccessRights,
}

impl FileSettings {
    /// Creates common file settings.
    pub const fn new(
        file_type: FileType,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
    ) -> Self {
        Self {
            file_type,
            communication_mode,
            access_rights,
        }
    }

    /// `DESFire` file type.
    pub const fn file_type(self) -> FileType {
        self.file_type
    }

    /// File communication mode.
    pub const fn communication_mode(self) -> CommunicationMode {
        self.communication_mode
    }

    /// File access rights.
    pub const fn access_rights(self) -> AccessRights {
        self.access_rights
    }
}
