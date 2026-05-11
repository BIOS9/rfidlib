/// 24-bit little-endian `DESFire` byte count or file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U24(u32);

impl U24 {
    /// Maximum value representable in a `DESFire` three-byte integer.
    pub const MAX: u32 = 0xFF_FFFF;

    /// Creates a bounded 24-bit value.
    pub const fn new(value: u32) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Decodes a little-endian 24-bit value.
    pub fn from_le_bytes(bytes: [u8; 3]) -> Self {
        Self(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
    }

    /// Encodes a little-endian 24-bit value.
    pub fn to_le_bytes(self) -> [u8; 3] {
        [
            u8::try_from(self.0 & 0x0000_00FF).expect("masked U24 byte fits in u8"),
            u8::try_from((self.0 >> 8) & 0x0000_00FF).expect("masked U24 byte fits in u8"),
            u8::try_from((self.0 >> 16) & 0x0000_00FF).expect("masked U24 byte fits in u8"),
        ]
    }

    /// Integer representation.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::types::U24;

    #[test]
    fn encodes_and_decodes_u24() {
        let value = U24::new(0x12_34_56).unwrap();

        assert_eq!(value.to_le_bytes(), [0x56, 0x34, 0x12]);
        assert_eq!(U24::from_le_bytes([0x56, 0x34, 0x12]), value);
        assert_eq!(value.as_u32(), 0x12_34_56);
    }

    #[test]
    fn rejects_values_outside_u24_range() {
        assert_eq!(U24::new(0x01_00_00_00), None);
    }
}
