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

/// Key settings for the currently selected `DESFire` application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySettings {
    raw_settings: u8,
    raw_key_count: u8,
    key_count: u8,
    key_type: ApplicationKeyType,
}

impl KeySettings {
    /// Creates key settings for use in `CreateApplication`.
    ///
    /// `raw_settings` is the lower four bits controlling master-key behaviour (0x0F = all defaults).
    pub fn new(raw_settings: u8, key_type: ApplicationKeyType, key_count: u8) -> Self {
        let type_bits: u8 = match key_type {
            ApplicationKeyType::TwoKey3Des => 0b00,
            ApplicationKeyType::ThreeKey3Des => 0b01,
            ApplicationKeyType::Aes => 0b10,
            ApplicationKeyType::Rfu => 0b11,
        };
        let raw_key_count = (type_bits << 6) | (key_count & 0x0F);
        Self {
            raw_settings,
            raw_key_count,
            key_count: key_count & 0x0F,
            key_type,
        }
    }

    /// Parses a `GetKeySettings` response.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 2 {
            return Err(Error::InvalidResponseLength);
        }

        let key_type = match data[1] >> 6 {
            0b00 => ApplicationKeyType::TwoKey3Des,
            0b01 => ApplicationKeyType::ThreeKey3Des,
            0b10 => ApplicationKeyType::Aes,
            0b11 => ApplicationKeyType::Rfu,
            _ => unreachable!("two-bit value"),
        };

        Ok(Self {
            raw_settings: data[0],
            raw_key_count: data[1],
            key_count: data[1] & 0x0F,
            key_type,
        })
    }

    /// Raw settings byte.
    pub const fn raw_settings(self) -> u8 {
        self.raw_settings
    }

    /// Raw key-count/key-type byte.
    pub const fn raw_key_count(self) -> u8 {
        self.raw_key_count
    }

    /// Number of keys configured for the selected application.
    pub const fn key_count(self) -> u8 {
        self.key_count
    }

    /// Key type encoded by the card.
    pub const fn key_type(self) -> ApplicationKeyType {
        self.key_type
    }

    /// Whether configuration changes are allowed.
    pub const fn configuration_changeable(self) -> bool {
        self.raw_settings & 0x08 != 0
    }

    /// Whether the master key is required to create or delete applications/files.
    pub const fn master_key_required_for_create_delete(self) -> bool {
        self.raw_settings & 0x04 == 0
    }

    /// Whether the master key is required to list applications/files or read key settings.
    pub const fn master_key_required_for_list(self) -> bool {
        self.raw_settings & 0x02 == 0
    }

    /// Whether create/delete operations are allowed without master-key authentication.
    pub const fn free_create_delete(self) -> bool {
        self.raw_settings & 0x04 != 0
    }

    /// Whether list/key-settings operations are allowed without master-key authentication.
    pub const fn free_list(self) -> bool {
        self.raw_settings & 0x02 != 0
    }

    /// Whether the master key itself is changeable.
    pub const fn master_key_changeable(self) -> bool {
        self.raw_settings & 0x01 != 0
    }
}

/// Application key family encoded in `GetKeySettings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationKeyType {
    TwoKey3Des,
    ThreeKey3Des,
    Aes,
    Rfu,
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::key::{ApplicationKeyType, KeySettings};

    #[test]
    fn parses_picc_key_settings() {
        let settings = KeySettings::parse(&[0x0F, 0x01]).unwrap();

        assert!(settings.configuration_changeable());
        assert!(!settings.master_key_required_for_create_delete());
        assert!(!settings.master_key_required_for_list());
        assert!(settings.free_create_delete());
        assert!(settings.free_list());
        assert!(settings.master_key_changeable());
        assert_eq!(settings.key_count(), 1);
        assert_eq!(settings.key_type(), ApplicationKeyType::TwoKey3Des);
    }

    #[test]
    fn parses_application_key_type() {
        let settings = KeySettings::parse(&[0x0F, 0x82]).unwrap();

        assert_eq!(settings.key_count(), 2);
        assert_eq!(settings.key_type(), ApplicationKeyType::Aes);
    }

    #[test]
    fn new_encodes_aes_key_count_correctly() {
        // Proxmark trace: --dstalgo aes --numkeys 1  ->  Key Set 2 = 0x81
        // 0x81 = 0b10_000001 = AES (bits 7:6) + 1 key (bits 3:0)
        let ks = KeySettings::new(0x0F, ApplicationKeyType::Aes, 1);
        assert_eq!(ks.raw_settings(), 0x0F);
        assert_eq!(ks.raw_key_count(), 0x81);
        assert_eq!(ks.key_count(), 1);
        assert_eq!(ks.key_type(), ApplicationKeyType::Aes);
    }

    #[test]
    fn parses_application_rights() {
        let settings = KeySettings::parse(&[0x0B, 0x81]).unwrap();

        assert!(settings.configuration_changeable());
        assert!(settings.master_key_required_for_create_delete());
        assert!(!settings.master_key_required_for_list());
        assert!(!settings.free_create_delete());
        assert!(settings.free_list());
        assert!(settings.master_key_changeable());
        assert_eq!(settings.key_count(), 1);
        assert_eq!(settings.key_type(), ApplicationKeyType::Aes);
    }
}
