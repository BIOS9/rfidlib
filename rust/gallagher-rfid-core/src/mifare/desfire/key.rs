use crate::mifare::desfire::error::Error;

/// `DESFire` key material with its cryptographic family encoded in the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Des([u8; 8]),
    TwoKey3Des([u8; 16]),
    ThreeKey3Des([u8; 24]),
    Aes128([u8; 16]),
}

/// `DESFire` key slot number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyNumber(u8);

impl KeyNumber {
    /// Highest regular `DESFire` key number.
    ///
    /// Access-condition nibbles reserve `0x0E` for free access and `0x0F` for
    /// no access.
    pub const MAX: u8 = 0x0D;

    /// Creates a validated key number.
    pub fn new(value: u8) -> Result<Self, Error> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(Error::InvalidKeyNumber(value))
        }
    }

    /// Raw key number byte.
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

impl From<KeyNumber> for u8 {
    fn from(value: KeyNumber) -> Self {
        value.0
    }
}
