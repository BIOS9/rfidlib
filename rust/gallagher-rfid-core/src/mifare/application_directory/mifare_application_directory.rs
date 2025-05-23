use core::iter;
use std::{io::Read, println};

use crate::mifare::classic::{Error, FourBlockOffset, FourBlockSector, KeyProvider, Sector, Tag};

use super::{card_publisher_sector::CardPublisherSector, mad_application_id::MadAid};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MadVersion {
    V1 = 1,
    V2,
}

impl TryFrom<u8> for MadVersion {
    type Error = MadError;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(MadVersion::V1),
            2 => Ok(MadVersion::V2),
            _ => Err(MadError::InvalidMadVersion(version)),
        }
    }
}

pub struct MifareApplicationDirectory {
    multi_application_card: bool,
    mad_version: MadVersion,
    card_publisher_sector: Option<CardPublisherSector>,
    applications: std::collections::BTreeMap<u8, MadAid>,
}

impl MifareApplicationDirectory {
    /// Default key A for Mifare Application Directory (MAD) sectors.
    pub const MAD_KEY_A: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    /// Default key B for Mifare Application Directory (MAD) sectors.
    pub const MAD_KEY_B: [u8; 6] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    /// Default access bits for Mifare Application Directory (MAD) sectors.
    /// Key A read, Key B read/write all blocks.
    pub const MAD_ACCESS_BITS: [u8; 3] = [0x78, 0x77, 0x88];

    // pub fn create(
    //     multi_application_card: bool,
    //     mad_version: MadVersion,
    //     card_publisher_sector: Option<CardPublisherSector>,
    //     applications: &std::collections::BTreeMap<u8, MadAid>,
    // ) -> Result<Self, MadError> {
    //     // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding
    //     // sector 0 since that means the value is absent).
    //     match mad_version {
    //         MadVersion::V1 => {
    //             if card_publisher_sector.into() >= 0x10 {
    //                 return Err(MadError::InvalidCardPublisherSectorForMadV1(
    //                     card_publisher_sector,
    //                 ));
    //             }
    //         }
    //         _ => {}
    //     }
    //     // e.g. check mad_version, card_publisher_sector validity, etc.

    //     // Build all applications with default FREE for missing entries...

    //     Ok(Self {
    //         multi_application_card,
    //         mad_version,
    //         card_publisher_sector,
    //         applications: applications.clone(),
    //     })
    // }

    pub fn read_from_tag<T: Tag>(
        tag: &mut T,
        key_provider: &impl KeyProvider,
    ) -> Result<Self, MadError> {
        // Sector 0 contains the MADv1.
        let mad_v1_sector = FourBlockSector::S0;
        key_provider.authenticate(tag, mad_v1_sector.into())?;

        // Block 3 contains the General Purpose Byte (GPB), keys and access conditions.
        let block3 = tag.read_block(mad_v1_sector.block(FourBlockOffset::B3))?;
        let general_purpose_byte: u8 = block3[9];

        match general_purpose_byte {
            0x69 => return Err(MadError::NotPersonalized),
            0x80 => return Err(MadError::MadMissing),
            _ => {}
        }

        // The MA bit of the GBP specifies if the card is multi-application or single-application.
        let multi_application_card = general_purpose_byte & 0b01000000 != 0;

        // The ADV bits of the GBP specify the MAD version.
        // 0b01 for V1, 0b10 for V2.
        let mad_version = MadVersion::try_from(general_purpose_byte & 0b00000011)?;

        // CRC calculation for MADv1 sector 0.
        // Expected CRC is offset by 16 bytes of manufacturer data in sector 0 (UID etc.).
        let block1 = tag.read_block(mad_v1_sector.block(FourBlockOffset::B1))?; // CRC and AIDs are stored in block 1.
        let block2 = tag.read_block(mad_v1_sector.block(FourBlockOffset::B2))?; // Rest of AIDs are stored in block 2.
        let expected_crc_0 = block1[0]; // Expected CRC of sector 0 MAD data.

        // We have to drop the first byte of the MADv1 data since that is the expected CRC.
        let mut mad_v1_data = [0u8; 32];
        mad_v1_data[..16].copy_from_slice(&block1);
        mad_v1_data[16..].copy_from_slice(&block2);
        if crc8(mad_v1_data.iter().skip(1)) != expected_crc_0 {
            return Err(MadError::CrcMismatch);
        }

        // Decode info byte, if it's non-zero, set the Card Publisher Sector (CPS).
        let sector0_info_byte = mad_v1_data[0] & 0b0011_1111;
        let mut card_publisher_sector = if sector0_info_byte == 0 {
            None
        } else {
            Some(sector0_info_byte)
        };

        // Parse AIDs for MADv1.
        // let sector0_aids: BTreeMap<FourBlockSector, MadAid> = mad_v1_data[1..] // Skip the info byte.
        //     .chunks(2)
        //     .enumerate()
        //     .map(|(i, chunk)| {
        //         let aid = MadAid::from_raw(chunk[1], chunk[0]);
        //         ((i + 1) as u8, aid)
        //     })
        //     .collect();

        // if MADv2 is present, decode that too.
        // MADv2 is just extra data on top of MADv1.
        if mad_version == MadVersion::V2 {
            // Sector 16 contains the MADv2.
            let mad_v2_sector = FourBlockSector::S16;
            key_provider.authenticate(tag, mad_v2_sector.into())?;

            // Read the entire sector
            let block0 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B0))?;
            let block1 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B1))?;
            let block2 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B2))?;

            let mut mad_v2_data = [0u8; 32];
            mad_v2_data[..16].copy_from_slice(&block1);
            mad_v2_data[16..].copy_from_slice(&block2);

            // CRC calculation for MADv2 sector 16.
            let expected_crc16 = block0[0]; // First byte in sector 16 is the CRC. Skip it for CRC input too.
            if crc8(mad_v2_data.iter().skip(1)) != expected_crc16 {
                return Err(MadError::CrcMismatch);
            }

            // Use the MADv2 CPS if it's present and non-zero.
            let sector16_info_byte = mad_v2_data[0] & 0b0011_1111; // Bits 6 and 7 of info byte are reserved, so ignore.
            if sector16_info_byte != 0 {
                card_publisher_sector = Some(sector16_info_byte);
            }

            // let sector16_aids: BTreeMap<u8, MadAid> = mad_v2_data[1..] // Skip info byte.
            //     .chunks(2)
            //     .enumerate()
            //     .map(|(i, chunk)| {
            //         let aid = MadAid::from_raw(chunk[1], chunk[0]);
            //         ((i + 17) as u8, aid)
            //     })
            //     .collect();

            // let mut all_aids = sector0_aids;
            // all_aids.extend(sector16_aids);

            // When MADv2, concatenate AIDs from MADv1 sector0 and MADv2 sector16
            // return create(
            //     multi_application_card,
            //     mad_version,
            //     card_publisher_sector,
            //     all_aids,
            // );
            println!("Valid MADv2!");
            todo!();
        }

        // create(
        //     multi_application_card,
        //     mad_version,
        //     card_publisher_sector,
        //     sector0_aids,
        // )
        println!("Valid MADv1!");
        todo!();
    }

    pub fn write_to_tag<T: Tag>(
        &self,
        tag: &mut T,
        key_provider: &impl KeyProvider,
    ) -> Result<(), MadError> {
        // Write MAD to blocks
        todo!()
    }

    pub fn multi_application_card(&self) -> bool {
        self.multi_application_card
    }
}

#[derive(Debug)]
pub enum MadError {
    NotPersonalized,
    MadMissing,
    InvalidMadVersion(u8),
    InvalidCardPublisherSectorForMadV1(CardPublisherSector),
    CrcMismatch,
    TagError(Error),
}

impl From<Error> for MadError {
    fn from(error: Error) -> Self {
        MadError::TagError(error)
    }
}

fn crc8<'a>(data: impl Iterator<Item = &'a u8>) -> u8 {
    const POLYNOMIAL: u8 = 0x1D; // MIFARE MAD polynomial
    const INIT_VALUE: u8 = 0xC7; // Initial value from MIFARE MAD spec

    data.fold(INIT_VALUE, |crc, &byte| {
        let mut crc = crc ^ byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ POLYNOMIAL
            } else {
                crc << 1
            };
        }
        crc
    })
}

#[cfg(test)]
mod test {
    use crate::mifare::application_directory::mifare_application_directory::crc8;

    #[test]
    fn crc8_value() {
        // Test cases created by generating random sets of bytes with length of MAD v1 sector 0 data
        // length (31 bytes), and MAD v2 sector 16 data length (47 bytes)
        // and then running each set through the Proxmark3 CRC8Mad code in
        // https://github.com/RfidResearchGroup/proxmark3/blob/master/common/crc.c
        // The first test case is an example from the MAD spec
        // https://www.nxp.com/docs/en/application-note/AN10787.pdf
        assert_eq!(crc8(b"\x01\x01\x08\x01\x08\x01\x08\x00\x00\x00\x00\x00\x00\x04\x00\x03\x10\x03\x10\x02\x10\x02\x10\x00\x00\x00\x00\x00\x00\x11\x30".into_iter()), 0x89);
        assert_eq!(crc8(b"\x5D\x0A\xA9\xC6\x2A\xE2\xBD\x2D\xF1\xCD\xB2\x6C\xE1\x9D\xF6\x89\x38\xDA\x1D\x91\xC6\x76\x32\xCA\xC6\x48\x4A\xA4\x75\xB7\x46".into_iter()), 0x05);
        assert_eq!(crc8(b"\x3A\x83\x0D\xE7\xB0\xFF\x77\x66\xB3\xED\x0F\xE5\xD2\x55\x55\x34\x13\x8A\x7A\xB0\x5E\x5E\x6A\xBD\xE3\xFD\xF3\xBA\xA3\x05\x85".into_iter()), 0x3B);
        assert_eq!(crc8(b"\x03\x3F\xA2\xF6\xC0\x80\x41\x55\xAE\x74\x74\x45\x38\xD3\xDF\xCF\xEA\xE7\xEA\x9B\xCE\xAD\x5A\xEF\x7B\x07\x81\xE4\x1B\x09\x44".into_iter()), 0x64);
        assert_eq!(crc8(b"\xCD\x2C\xDC\x1C\xCC\xC1\xC5\xAB\x85\xA1\x99\x8B\xD4\x10\x00\x11\x9E\x03\xA1\x8A\xCC\x85\xC8\x8C\xE0\x00\xB7\x45\x17\x07\xF6".into_iter()), 0xE7);
        assert_eq!(crc8(b"\x3C\x36\xB2\x2C\x5C\xD3\xBC\x2D\x99\xBD\x8C\xFF\xB2\x2E\x30\xA0\xE2\xDF\x4E\x70\xCE\xBF\x8F\x82\x35\x43\x65\xCF\x13\x06\xC2".into_iter()), 0x78);
        assert_eq!(crc8(b"\xEB\xB8\x3C\x69\xE9\xCE\x8E\x40\x38\xEA\xFF\xAC\x11\xC4\xD9\x67\x2F\x12\xE3\x2E\x98\xBF\x67\xE4\xC5\x61\x1A\x5A\xAA\xA3\xBA".into_iter()), 0x13);
        assert_eq!(crc8(b"\x2A\xD8\xDE\x0B\x5C\xC3\x70\xB5\x0E\xD2\x6C\x3F\xD3\xC8\xD9\x5B\xFC\x83\x77\x09\xC3\x10\xF6\xB9\x23\xB9\x44\x73\xFA\x27\x55".into_iter()), 0xDE);
        assert_eq!(crc8(b"\x74\x3B\xD3\x86\x3F\x76\x3A\xBE\xE9\x6C\x6D\x80\x04\x88\xFB\x55\x73\xE2\x6D\x97\x21\xA1\xAE\xCB\xFD\x66\xDF\xCC\xBD\x0D\x07".into_iter()), 0x6D);
        assert_eq!(crc8(b"\x60\xEA\x81\x4D\x3E\x8F\x05\xFE\xF1\xAB\x52\x44\xD3\x30\xFA\x76\x8C\xF1\x3D\xCE\xD4\x50\x57\x10\xB1\x7D\x10\x55\x93\xE3\x79".into_iter()), 0x74);
        assert_eq!(crc8(b"\x8D\x2B\x76\xBF\x9D\x47\x8E\xC6\x91\x19\xE8\xAA\xED\xB3\x01\x89\xBB\x9D\xDA\xDA\x70\x3E\xF9\xE0\xE7\x51\xC0\x36\xF1\x44\x8A".into_iter()), 0x31);
        assert_eq!(crc8(b"\x54\x3D\x2B\x50\xC7\x0B\xF7\x0B\x2B\x80\x94\x5D\xBB\x07\x7E\xD3\xBB\xAF\xE1\x63\xBA\x98\xD6\x4D\x64\x5E\x51\x2C\x58\x08\x0E\x47\x3E\x52\xA5\x8D\x92\xB2\x43\x3B\x6D\x53\x02\x8C\x12\xD0\xC4".into_iter()), 0xC8);
        assert_eq!(crc8(b"\x77\xEE\xCF\x65\x1E\x46\x9C\xDB\x6B\xC3\x06\x16\xB4\xF7\x63\x1C\x6B\x07\xFD\xCA\x44\x19\x31\x19\x7E\x87\x94\x26\xF8\xD1\xDA\xAD\xD3\xA3\x1D\x5A\x5D\x99\xA7\xDA\xD0\xA4\x97\xA4\xBE\x34\x4F".into_iter()), 0x02);
        assert_eq!(crc8(b"\xB1\x4E\x34\x69\x6C\xA2\x5D\x83\xA5\xF6\xA6\x4B\xB1\x10\x7A\x1D\x11\xBE\x15\x91\x31\x3E\xFE\xD7\xA1\x88\xB5\x54\x0F\xF2\xC1\xAB\xFF\xD8\x6D\x75\xA1\xD2\xE8\x9C\x66\xE4\x9F\x0B\x35\x09\x29".into_iter()), 0x99);
        assert_eq!(crc8(b"\x66\xDB\x7A\x27\xC7\x06\x4A\xED\xE4\xE0\x48\xC4\x04\x38\xF5\x65\xBA\x5A\xB4\xFC\xD6\x54\xA0\xBC\xA5\xB8\x70\x7E\xE7\xF3\x3A\x38\x37\xFC\xD7\xE4\x3E\xE6\x9D\xF1\x48\x87\xE5\x8E\x81\x81\xCB".into_iter()), 0x6D);
        assert_eq!(crc8(b"\x58\x7A\xB6\xD5\xC0\x16\x2B\x29\x4B\xA4\x4D\xD4\x42\xB0\x89\xD4\xCA\xC8\x29\x91\xAF\xBD\x7D\xEE\xE6\xE3\x7D\xC0\x17\x7B\x09\x6F\x33\x6A\x47\x4C\x30\x26\xA9\x46\x34\x97\x12\x1C\x7D\x80\x85".into_iter()), 0xB1);
        assert_eq!(crc8(b"\x72\x93\xF4\xF1\xD9\x27\xA2\x50\x30\x2D\x7C\x98\x02\x05\xBE\x13\x50\xDA\x9B\x09\x12\xE3\xA6\x23\x29\xA5\xF4\x80\x70\x62\x7B\x61\x9F\x15\xDE\x5F\x9E\xCA\x36\xDE\x0C\xCA\xFA\x63\x13\x8A\xA2".into_iter()), 0x11);
        assert_eq!(crc8(b"\x9B\x41\x39\x95\xAA\xC0\x7C\x55\x71\x87\x48\xB8\xA0\x28\x7A\x12\x73\x07\x9A\x3A\xCB\xC0\x49\x78\x92\xE5\x24\x82\x7A\x57\x80\x94\x24\x5B\xE9\xC9\x28\xBF\x05\xAE\x76\xD7\xB2\x3F\xF2\x26\x14".into_iter()), 0xD0);
        assert_eq!(crc8(b"\x20\x1C\xF6\x9D\xA3\xEB\x4B\x85\x0C\xC1\xB4\x39\xC4\x64\x5B\x16\x61\x14\xDC\xEA\xF3\xB6\x9D\x40\x31\xE9\x3B\x22\x2C\xD5\x52\x52\x21\xA4\xDC\xE7\x16\x0C\x48\x30\x86\x2C\xA4\x92\x44\x92\x53".into_iter()), 0x87);
        assert_eq!(crc8(b"\x46\x87\xA7\xB7\x19\xA2\x76\xA6\x53\x1F\x8D\x8C\xDD\x67\x9B\x1B\xAC\x35\x0E\xAC\xB2\x82\x92\x25\x47\xAA\x68\x51\x09\xCA\xEB\xC5\x20\x8F\x2E\xC2\x97\xF7\x03\x72\xD9\xC6\x5B\x5B\x2F\x04\xBB".into_iter()), 0xE8);
        assert_eq!(crc8(b"\x6E\xF1\x9C\x0D\xCC\xF4\x73\x67\xBE\x62\xC4\xBA\x37\x4B\xAF\x0D\x8A\xE6\xA1\xA7\xC5\xC8\xB9\xC7\x87\xF3\x80\xEC\x42\x46\x5A\xB7\x06\x2A\x33\xC8\x30\x92\xE8\x7E\xE4\x73\xFC\x1A\x5C\xDA\xFA".into_iter()), 0x14);
    }
}
