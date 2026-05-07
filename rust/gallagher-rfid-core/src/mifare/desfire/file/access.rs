use crate::mifare::desfire::key::KeyNumber;

/// One `DESFire` file access condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCondition {
    Key(KeyNumber),
    Free,
    Never,
}

impl AccessCondition {
    /// Decodes one access-rights nibble.
    pub fn from_nibble(value: u8) -> Self {
        match value {
            0x00..=KeyNumber::MAX => Self::Key(KeyNumber::new(value).unwrap()),
            0x0E => Self::Free,
            0x0F => Self::Never,
            _ => unreachable!("access condition is a four-bit value"),
        }
    }

    /// Encodes this condition as a four-bit nibble.
    pub fn to_nibble(self) -> u8 {
        match self {
            Self::Key(n) => n.as_byte(),
            Self::Free => 0x0E,
            Self::Never => 0x0F,
        }
    }
}

/// Access conditions for a `DESFire` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    read: AccessCondition,
    write: AccessCondition,
    read_write: AccessCondition,
    change: AccessCondition,
}

impl AccessRights {
    /// Creates access rights from optional key requirements.
    pub const fn new(
        read: AccessCondition,
        write: AccessCondition,
        read_write: AccessCondition,
        change: AccessCondition,
    ) -> Self {
        Self {
            read,
            write,
            read_write,
            change,
        }
    }

    /// Decodes the two access-rights bytes from `GetFileSettings`.
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self {
            read_write: AccessCondition::from_nibble(bytes[0] >> 4),
            change: AccessCondition::from_nibble(bytes[0] & 0x0F),
            read: AccessCondition::from_nibble(bytes[1] >> 4),
            write: AccessCondition::from_nibble(bytes[1] & 0x0F),
        }
    }

    /// Required condition for read access.
    pub const fn read(self) -> AccessCondition {
        self.read
    }

    /// Required condition for write access.
    pub const fn write(self) -> AccessCondition {
        self.write
    }

    /// Required condition for combined read/write access.
    pub const fn read_write(self) -> AccessCondition {
        self.read_write
    }

    /// Required condition for changing file settings.
    pub const fn change(self) -> AccessCondition {
        self.change
    }

    /// Encodes access rights to the two-byte `DESFire` wire format.
    pub fn to_bytes(self) -> [u8; 2] {
        [
            (self.read_write.to_nibble() << 4) | self.change.to_nibble(),
            (self.read.to_nibble() << 4) | self.write.to_nibble(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        file::{AccessCondition, AccessRights},
        key::KeyNumber,
    };

    #[test]
    fn access_rights_round_trips_through_bytes() {
        // from_bytes -> to_bytes must be identity.
        for b0 in [0x0F_u8, 0x1F, 0xEF, 0xFF] {
            for b1 in [0x00_u8, 0xE0, 0x81, 0xFF] {
                let bytes = [b0, b1];
                assert_eq!(AccessRights::from_bytes(bytes).to_bytes(), bytes);
            }
        }
    }

    #[test]
    fn decodes_access_rights_bytes() {
        let rights = AccessRights::from_bytes([0x1F, 0xE2]);

        assert_eq!(
            rights.read_write(),
            AccessCondition::Key(KeyNumber::new(1).unwrap())
        );
        assert_eq!(rights.change(), AccessCondition::Never);
        assert_eq!(rights.read(), AccessCondition::Free);
        assert_eq!(
            rights.write(),
            AccessCondition::Key(KeyNumber::new(2).unwrap())
        );
    }
}
