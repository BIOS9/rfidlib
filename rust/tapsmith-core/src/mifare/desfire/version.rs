use crate::mifare::desfire::error::Error;

/// Parsed response from `GetVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    hardware: VersionPart,
    software: VersionPart,
    uid: [u8; 7],
    batch_number: [u8; 5],
    production_week: u8,
    production_year: u8,
}

impl VersionInfo {
    /// Parses the complete chained `GetVersion` response.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 28 {
            return Err(Error::InvalidResponseLength);
        }

        let hardware = VersionPart::parse(&data[0..7])?;
        let software = VersionPart::parse(&data[7..14])?;
        let uid = data[14..21].try_into().expect("slice length is checked");
        let batch_number = data[21..26].try_into().expect("slice length is checked");

        Ok(Self {
            hardware,
            software,
            uid,
            batch_number,
            production_week: data[26],
            production_year: data[27],
        })
    }

    /// Hardware version block.
    pub const fn hardware(self) -> VersionPart {
        self.hardware
    }

    /// Software version block.
    pub const fn software(self) -> VersionPart {
        self.software
    }

    /// Card UID bytes.
    pub const fn uid(self) -> [u8; 7] {
        self.uid
    }

    /// Batch number bytes.
    pub const fn batch_number(self) -> [u8; 5] {
        self.batch_number
    }

    /// Production week value as reported by the card.
    pub const fn production_week(self) -> u8 {
        self.production_week
    }

    /// Production week decoded from the BCD value reported by the card.
    pub const fn production_week_decimal(self) -> u8 {
        bcd_to_decimal(self.production_week)
    }

    /// Production year value as reported by the card.
    pub const fn production_year(self) -> u8 {
        self.production_year
    }

    /// Production year decoded from the BCD value reported by the card.
    pub const fn production_year_decimal(self) -> u8 {
        bcd_to_decimal(self.production_year)
    }
}

/// One seven-byte version block from `GetVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPart {
    vendor_id: u8,
    card_type: u8,
    subtype: u8,
    major: u8,
    minor: u8,
    storage_size: u8,
    protocol: u8,
}

impl VersionPart {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 7 {
            return Err(Error::InvalidResponseLength);
        }

        Ok(Self {
            vendor_id: data[0],
            card_type: data[1],
            subtype: data[2],
            major: data[3],
            minor: data[4],
            storage_size: data[5],
            protocol: data[6],
        })
    }

    /// IC manufacturer id.
    pub const fn vendor_id(self) -> u8 {
        self.vendor_id
    }

    /// Hardware or software type byte.
    pub const fn card_type(self) -> u8 {
        self.card_type
    }

    /// Hardware or software subtype byte.
    pub const fn subtype(self) -> u8 {
        self.subtype
    }

    /// Major version.
    pub const fn major(self) -> u8 {
        self.major
    }

    /// Major version decoded from the BCD value reported by the card.
    pub const fn major_decimal(self) -> u8 {
        bcd_to_decimal(self.major)
    }

    /// Minor version.
    pub const fn minor(self) -> u8 {
        self.minor
    }

    /// Minor version decoded from the BCD value reported by the card.
    pub const fn minor_decimal(self) -> u8 {
        bcd_to_decimal(self.minor)
    }

    /// Raw storage-size byte.
    pub const fn storage_size(self) -> u8 {
        self.storage_size
    }

    /// Protocol byte.
    pub const fn protocol(self) -> u8 {
        self.protocol
    }
}

const fn bcd_to_decimal(value: u8) -> u8 {
    ((value >> 4) * 10) + (value & 0x0F)
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::version::VersionInfo;

    #[test]
    fn parses_get_version_response() {
        let data = [
            0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05, 0x04, 0x01, 0x01, 0x01, 0x05, 0x18, 0x05,
            0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x10, 0x20, 0x30, 0x40, 0x50, 0x24, 0x16,
        ];

        let version = VersionInfo::parse(&data).unwrap();

        assert_eq!(version.hardware().vendor_id(), 0x04);
        assert_eq!(version.software().minor(), 0x05);
        assert_eq!(version.hardware().major_decimal(), 1);
        assert_eq!(version.software().minor_decimal(), 5);
        assert_eq!(version.uid(), [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(version.batch_number(), [0x10, 0x20, 0x30, 0x40, 0x50]);
        assert_eq!(version.production_week(), 0x24);
        assert_eq!(version.production_year(), 0x16);
        assert_eq!(version.production_week_decimal(), 24);
        assert_eq!(version.production_year_decimal(), 16);
    }
}
