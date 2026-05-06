/// `DESFire` status bytes returned by the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    OperationOk,
    NoChanges,
    OutOfMemory,
    IllegalCommandCode,
    IntegrityError,
    NoSuchKey,
    LengthError,
    PermissionDenied,
    ParameterError,
    ApplicationNotFound,
    ApplicationIntegrityError,
    AuthenticationError,
    AdditionalFrame,
    BoundaryError,
    PiccIntegrityError,
    CommandAborted,
    PiccDisabled,
    CountError,
    DuplicateError,
    EepromError,
    FileNotFound,
    FileIntegrityError,
    Unknown(u8),
}

impl Status {
    /// Raw `DESFire` status byte.
    pub fn as_byte(self) -> u8 {
        match self {
            Status::OperationOk => 0x00,
            Status::NoChanges => 0x0C,
            Status::OutOfMemory => 0x0E,
            Status::IllegalCommandCode => 0x1C,
            Status::IntegrityError => 0x1E,
            Status::NoSuchKey => 0x40,
            Status::LengthError => 0x7E,
            Status::PermissionDenied => 0x9D,
            Status::ParameterError => 0x9E,
            Status::ApplicationNotFound => 0xA0,
            Status::ApplicationIntegrityError => 0xA1,
            Status::AuthenticationError => 0xAE,
            Status::AdditionalFrame => 0xAF,
            Status::BoundaryError => 0xBE,
            Status::PiccIntegrityError => 0xC1,
            Status::CommandAborted => 0xCA,
            Status::PiccDisabled => 0xCD,
            Status::CountError => 0xCE,
            Status::DuplicateError => 0xDE,
            Status::EepromError => 0xEE,
            Status::FileNotFound => 0xF0,
            Status::FileIntegrityError => 0xF1,
            Status::Unknown(value) => value,
        }
    }

    /// Returns true when the status allows command processing to continue.
    pub fn is_ok(self) -> bool {
        matches!(self, Status::OperationOk)
    }
}

impl From<u8> for Status {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Status::OperationOk,
            0x0C => Status::NoChanges,
            0x0E => Status::OutOfMemory,
            0x1C => Status::IllegalCommandCode,
            0x1E => Status::IntegrityError,
            0x40 => Status::NoSuchKey,
            0x7E => Status::LengthError,
            0x9D => Status::PermissionDenied,
            0x9E => Status::ParameterError,
            0xA0 => Status::ApplicationNotFound,
            0xA1 => Status::ApplicationIntegrityError,
            0xAE => Status::AuthenticationError,
            0xAF => Status::AdditionalFrame,
            0xBE => Status::BoundaryError,
            0xC1 => Status::PiccIntegrityError,
            0xCA => Status::CommandAborted,
            0xCD => Status::PiccDisabled,
            0xCE => Status::CountError,
            0xDE => Status::DuplicateError,
            0xEE => Status::EepromError,
            0xF0 => Status::FileNotFound,
            0xF1 => Status::FileIntegrityError,
            _ => Status::Unknown(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::status::Status;

    #[test]
    fn maps_known_status_bytes() {
        assert_eq!(Status::from(0x00), Status::OperationOk);
        assert_eq!(Status::from(0xAF), Status::AdditionalFrame);
        assert_eq!(Status::from(0xF0), Status::FileNotFound);
    }

    #[test]
    fn preserves_unknown_status_byte() {
        assert_eq!(Status::from(0x12), Status::Unknown(0x12));
        assert_eq!(Status::Unknown(0x12).as_byte(), 0x12);
    }
}
