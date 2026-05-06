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
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        file::{AccessCondition, AccessRights},
        key::KeyNumber,
    };

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
