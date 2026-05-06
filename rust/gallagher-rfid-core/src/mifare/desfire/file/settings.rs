use crate::mifare::desfire::{error::Error, file::AccessRights, types::U24};

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
    details: FileSettingsDetails,
}

impl FileSettings {
    /// Creates common file settings.
    pub const fn new(
        file_type: FileType,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        details: FileSettingsDetails,
    ) -> Self {
        Self {
            file_type,
            communication_mode,
            access_rights,
            details,
        }
    }

    /// Parses the `GetFileSettings` response body.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::InvalidResponseLength);
        }

        let file_type = FileType::try_from(data[0])?;
        let communication_mode = CommunicationMode::try_from(data[1])?;
        let access_rights = AccessRights::from_bytes([data[2], data[3]]);

        let details = match file_type {
            FileType::StandardData | FileType::BackupData => {
                let size = parse_u24(data, 4)?;
                FileSettingsDetails::Data { size }
            }
            FileType::Value => {
                if data.len() < 17 {
                    return Err(Error::InvalidResponseLength);
                }
                FileSettingsDetails::Value {
                    lower_limit: parse_i32(data, 4)?,
                    upper_limit: parse_i32(data, 8)?,
                    limited_credit_value: parse_i32(data, 12)?,
                    limited_credit_enabled: data[16] != 0,
                }
            }
            FileType::LinearRecord | FileType::CyclicRecord => FileSettingsDetails::Record {
                record_size: parse_u24(data, 4)?,
                max_records: parse_u24(data, 7)?,
                current_records: parse_u24(data, 10)?,
            },
        };

        Ok(Self::new(
            file_type,
            communication_mode,
            access_rights,
            details,
        ))
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

    /// Type-specific file settings.
    pub const fn details(self) -> FileSettingsDetails {
        self.details
    }
}

/// Type-specific `DESFire` file settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSettingsDetails {
    Data {
        size: U24,
    },
    Value {
        lower_limit: i32,
        upper_limit: i32,
        limited_credit_value: i32,
        limited_credit_enabled: bool,
    },
    Record {
        record_size: U24,
        max_records: U24,
        current_records: U24,
    },
}

fn parse_u24(data: &[u8], offset: usize) -> Result<U24, Error> {
    let bytes = data
        .get(offset..offset + 3)
        .ok_or(Error::InvalidResponseLength)?
        .try_into()
        .expect("slice length is checked");
    Ok(U24::from_le_bytes(bytes))
}

fn parse_i32(data: &[u8], offset: usize) -> Result<i32, Error> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(Error::InvalidResponseLength)?
        .try_into()
        .expect("slice length is checked");
    Ok(i32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        file::{AccessCondition, CommunicationMode, FileSettings, FileSettingsDetails, FileType},
        key::KeyNumber,
        types::U24,
    };

    #[test]
    fn parses_standard_data_file_settings() {
        let settings = FileSettings::parse(&[0x00, 0x00, 0x12, 0xE3, 0x34, 0x12, 0x00]).unwrap();

        assert_eq!(settings.file_type(), FileType::StandardData);
        assert_eq!(settings.communication_mode(), CommunicationMode::Plain);
        assert_eq!(
            settings.access_rights().read_write(),
            AccessCondition::Key(KeyNumber::new(1).unwrap())
        );
        assert_eq!(settings.access_rights().read(), AccessCondition::Free);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(0x1234).unwrap()
            }
        );
    }

    #[test]
    fn parses_record_file_settings() {
        let settings = FileSettings::parse(&[
            0x03, 0x03, 0xEE, 0xEF, 0x10, 0x00, 0x00, 0x20, 0x00, 0x00, 0x03, 0x00, 0x00,
        ])
        .unwrap();

        assert_eq!(settings.file_type(), FileType::LinearRecord);
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
        assert_eq!(settings.access_rights().read_write(), AccessCondition::Free);
        assert_eq!(settings.access_rights().change(), AccessCondition::Free);
        assert_eq!(settings.access_rights().write(), AccessCondition::Never);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Record {
                record_size: U24::new(16).unwrap(),
                max_records: U24::new(32).unwrap(),
                current_records: U24::new(3).unwrap()
            }
        );
    }
}
