use crate::mifare::desfire::error::Error;

/// Three-byte `DESFire` application identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationId([u8; 3]);

impl ApplicationId {
    /// PICC-level application id.
    pub const PICC: Self = Self([0x00, 0x00, 0x00]);

    /// Creates an application id from raw little-endian `DESFire` bytes.
    pub const fn from_bytes(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }

    /// Creates an application id from a 24-bit integer.
    pub fn new(value: u32) -> Result<Self, Error> {
        if value > 0xFF_FFFF {
            return Err(Error::InvalidApplicationId(value));
        }

        let b0 = u8::try_from(value & 0x0000_00FF).expect("masked AID byte fits in u8");
        let b1 = u8::try_from((value >> 8) & 0x0000_00FF).expect("masked AID byte fits in u8");
        let b2 = u8::try_from((value >> 16) & 0x0000_00FF).expect("masked AID byte fits in u8");
        Ok(Self([b0, b1, b2]))
    }

    /// Raw little-endian `DESFire` AID bytes.
    pub const fn as_bytes(self) -> [u8; 3] {
        self.0
    }

    /// Integer representation of the application id.
    pub fn as_u32(self) -> u32 {
        u32::from(self.0[0]) | (u32::from(self.0[1]) << 8) | (u32::from(self.0[2]) << 16)
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{application::ApplicationId, error::Error};

    #[test]
    fn creates_application_id_from_u24() {
        let aid = ApplicationId::new(0x12_34_56).unwrap();

        assert_eq!(aid.as_bytes(), [0x56, 0x34, 0x12]);
        assert_eq!(aid.as_u32(), 0x12_34_56);
    }

    #[test]
    fn rejects_application_id_outside_u24_range() {
        assert_eq!(
            ApplicationId::new(0x01_00_00_00),
            Err(Error::InvalidApplicationId(0x01_00_00_00))
        );
    }
}
