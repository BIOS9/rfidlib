use crate::mifare::application_directory::non_mad_sector::NonMadSector;
use crate::mifare::classic::{
    Error, FourBlockOffset, FourBlockSector, KeyProvider, Sector, SixteenBlockSector, Tag,
};
use heapless::LinearMap;

use super::mad_application_id::{AdministrationCode, MadAid, MadAidError};

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

/// Max possible number of Application IDs in MIFARE Application Directory.
const MAX_AID_COUNT: usize = 38;

pub struct MifareApplicationDirectory {
    pub multi_application_card: bool,
    pub mad_version: MadVersion,
    pub card_publisher_sector: Option<NonMadSector>,
    applications: LinearMap<NonMadSector, MadAid, MAX_AID_COUNT>,
}

impl MifareApplicationDirectory {
    /// Default key A for MIFARE Application Directory (MAD) sectors.
    pub const MAD_KEY_A: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    /// Default key B for MIFARE Application Directory (MAD) sectors.
    pub const MAD_KEY_B: [u8; 6] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    /// Default access bits for MIFARE Application Directory (MAD) sectors.
    /// Key A read, Key B read/write all blocks.
    pub const MAD_ACCESS_BITS: [u8; 3] = [0x78, 0x77, 0x88];

    pub fn new(
        multi_application_card: bool,
        mad_version: MadVersion,
        card_publisher_sector: Option<NonMadSector>,
        applications: LinearMap<NonMadSector, MadAid, MAX_AID_COUNT>,
    ) -> Result<Self, MadError> {
        // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding
        // sector 0 since that means the value is absent).
        if let Some(cps) = card_publisher_sector {
            if mad_version == MadVersion::V1 && u8::from(cps) > 15 {
                return Err(MadError::InvalidCardPublisherSectorForMadV1(cps.into()));
            }
        }

        // The maximum sector which can contain an application.
        let max_application_sector = if mad_version == MadVersion::V1 {
            FourBlockSector::S15 as u8
        } else {
            SixteenBlockSector::S39 as u8
        };

        // Max sector 15 for MADv1, sector 39 for MADv2.
        if mad_version == MadVersion::V1 {
            if let Some((&sector, _)) = applications
                .iter()
                .find(|(&sector, _)| u8::from(sector) > max_application_sector)
            {
                return Err(MadError::InvalidApplicationSectorForMadV1(sector.into()));
            }
        }

        Ok(Self {
            multi_application_card,
            mad_version,
            card_publisher_sector,
            applications,
        })
    }

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
        let mad_v1_data = {
            let mut data = [0u8; 32];
            data[..16].copy_from_slice(&block1);
            data[16..].copy_from_slice(&block2);
            data
        };

        if crc8(mad_v1_data.iter().skip(1)) != expected_crc_0 {
            return Err(MadError::CrcMismatch);
        }

        // Decode info byte, if it's non-zero, set the Card Publisher Sector (CPS).
        let cps_data = mad_v1_data[0] & 0b0000_1111; // MADv1 CPS is only four bits since MIFARE Classic 1K only has 16 sectors.
        let card_publisher_sector_v1 = Sector::try_from(cps_data)
            .ok()
            .and_then(|sec| NonMadSector::try_from(sec).ok());

        // Parse card applications for MADv1.
        let mut applications: LinearMap<NonMadSector, MadAid, MAX_AID_COUNT> = LinearMap::new();
        // Skip the CRC and info byte, and break into 2 byte chunks.
        for (i, chunk) in mad_v1_data[2..].chunks(2).enumerate() {
            let arr: [u8; 2] = match chunk.try_into() {
                Ok(a) => a,
                // It should not be possible to get a chunk that isn't two bytes because a block is always 16 bytes which divides evenly into 2 byte chunks.
                Err(_) => unreachable!(
                    "Invalid AID size, expected chunk of two bytes, got {}",
                    chunk.len()
                ),
            };

            let aid = MadAid::try_from_u8(arr[1], arr[0])?;

            // Ignore sectors with no application.
            if aid != MadAid::CardAdministration(AdministrationCode::Free) {
                let sector = Sector::try_from(i as u8 + 1)?; // +1 to skip sector 0.
                let non_mad = NonMadSector::try_from(sector)
                    .map_err(|_| MadError::InvalidApplicationSector(sector))?;

                // It should not be possible to end up with duplicate sectors in this map since we're enumerating over a range.
                if let Err(_) = applications.insert(non_mad, aid) {
                    unreachable!("Sector already exists in AID map.")
                }
            }
        }

        // If MADv2 is present, decode that too.
        // MADv2 is just extra data on top of MADv1.
        if mad_version == MadVersion::V2 {
            // Sector 16 contains the MADv2.
            let mad_v2_sector = FourBlockSector::S16;
            key_provider.authenticate(tag, mad_v2_sector.into())?;

            // Read the entire sector
            let block0 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B0))?;
            let block1 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B1))?;
            let block2 = tag.read_block(mad_v2_sector.block(FourBlockOffset::B2))?;

            let mad_v2_data = {
                let mut data = [0u8; 48];
                data[..16].copy_from_slice(&block0);
                data[16..32].copy_from_slice(&block1);
                data[48..].copy_from_slice(&block2);
                data
            };

            // CRC calculation for MADv2 sector 16.
            let expected_crc16 = mad_v2_data[0]; // First byte in sector 16 is the CRC. Skip it for CRC input too.
            if crc8(mad_v2_data.iter().skip(1)) != expected_crc16 {
                return Err(MadError::CrcMismatch);
            }

            // Decode MADv2 info byte, if it's non-zero, set the Card Publisher Sector (CPS).
            let cps_data = mad_v2_data[1] & 0b0011_1111; // MADv2 is 6 bits. Bits 6 and 7 of info byte are reserved, so ignore.
            let card_publisher_sector = Sector::try_from(cps_data) // Try to decode CPS, if it's invalid, just ignore it, we can continue anyway.
                .ok()
                .and_then(|sec| NonMadSector::try_from(sec).ok())
                .or(card_publisher_sector_v1);

            // Parse MADv2 applications.
            // Skip the CRC and info byte, and break into 2 byte chunks.
            for (i, chunk) in mad_v2_data[2..].chunks(2).enumerate() {
                let arr: [u8; 2] = match chunk.try_into() {
                    Ok(a) => a,
                    // It should not be possible to get a chunk that isn't two bytes because a block is always 16 bytes which divides evenly into 2 byte chunks.
                    Err(_) => unreachable!("Invalid AID size, expected chunk of two bytes"),
                };

                let aid = MadAid::try_from_u8(arr[1], arr[0])?;

                // Ignore sectors with no application.
                if aid != MadAid::CardAdministration(AdministrationCode::Free) {
                    let sector = Sector::try_from(i as u8 + 17)?; // +17 to skip MADv1 sectors and sector 16.
                    let non_mad = NonMadSector::try_from(sector)
                        .map_err(|_| MadError::InvalidApplicationSector(sector))?;

                    // It should not be possible to end up with duplicate sectors in this map since we're enumerating over a range.
                    if let Err(_) = applications.insert(non_mad, aid) {
                        unreachable!("Sector already exists in AID map.")
                    }
                }
            }

            Self::new(
                multi_application_card,
                mad_version,
                card_publisher_sector,
                applications,
            )
        } else {
            Self::new(
                multi_application_card,
                mad_version,
                card_publisher_sector_v1,
                applications,
            )
        }
    }

    pub fn write_to_tag<T: Tag>(
        &self,
        _tag: &mut T,
        _key_provider: &impl KeyProvider,
    ) -> Result<(), MadError> {
        // Write MAD to blocks
        todo!()
    }
}

#[derive(Debug)]
pub enum MadError {
    NotPersonalized,
    MadMissing,
    InvalidMadVersion(u8),
    InvalidCardPublisherSectorForMadV1(Sector),
    InvalidApplicationSectorForMadV1(Sector),
    InvalidApplication(MadAidError),
    InvalidApplicationSector(Sector),
    CrcMismatch,
    TagError(Error),
}

impl From<Error> for MadError {
    fn from(error: Error) -> Self {
        MadError::TagError(error)
    }
}

impl From<MadAidError> for MadError {
    fn from(error: MadAidError) -> Self {
        MadError::InvalidApplication(error)
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
    use crate::mifare::application_directory::{MadVersion, MifareApplicationDirectory};
    use crate::mifare::classic::{
        Block, Error, FourBlockSector, KeyProvider, KeyType, Sector, Tag,
    };

    struct MockClassic1k<'a> {
        key: &'a [u8; 6],
        sector0: &'a [u8; 64],
    }

    impl<'a> Tag for MockClassic1k<'a> {
        fn authenticate(
            &mut self,
            sector: Sector,
            key: &[u8; 6],
            key_type: KeyType,
        ) -> Result<(), Error> {
            if key.eq(self.key) && sector == FourBlockSector::S0.into() && key_type == KeyType::KeyA
            {
                Ok(())
            } else {
                panic!("Unexpected authentication")
            }
        }

        fn read_block(&mut self, block: Block) -> Result<[u8; 16], Error> {
            let mut out = [0u8; 16];
            match u8::from(block) {
                0 => out.copy_from_slice(&self.sector0[0..16]),
                1 => out.copy_from_slice(&self.sector0[16..32]),
                2 => out.copy_from_slice(&self.sector0[32..48]),
                3 => out.copy_from_slice(&self.sector0[48..64]),
                _ => panic!("Unexpected block read"),
            };
            Ok(out)
        }

        fn write_block(&mut self, _: Block, _: [u8; 16]) -> Result<(), Error> {
            panic!("Unexpected write");
        }
    }

    struct MockKeyProvider<'a> {
        key_type: KeyType,
        key: &'a [u8; 6],
    }

    impl<'a> KeyProvider for MockKeyProvider<'a> {
        fn authenticate<T: Tag>(&self, tag: &mut T, sector: Sector) -> Result<(), Error> {
            tag.authenticate(sector, self.key, self.key_type)
        }
    }

    const TEST_MAD_A_KEY: &[u8; 6] = b"\xA0\xA1\xA2\xA3\xA4\xA5";
    const TEST_MAD_B_KEY: &[u8; 6] = b"\xB0\xB1\xB2\xB3\xB4\xB5";
    const VALID_SECTOR_0: &[u8; 64] = b"\x9D\x49\x91\x16\xDE\x28\x02\x00\xE3\x27\x00\x20\x00\x00\x00\x17\xCD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x48\x12\x48\x00\x00\x00\x00\x00\x00\x78\x77\x88\xC1\x00\x00\x00\x00\x00\x00";

    const DEFAULT_READ_KEY_PROVIDER: MockKeyProvider = MockKeyProvider {
        key_type: KeyType::KeyA,
        key: TEST_MAD_A_KEY,
    };
    //   private val validSector0MoreAids =
    //       ("9D 49 91 16 DE 28 02 00 E3 27 00 20 00 00 00 17" +
    //               "23 00 01 FE 02 FD 03 FC 04 FB 05 FA 06 F9 07 F8" +
    //               "08 F7 09 F6 0A F5 0B F4 0C F3 0D F2 0E F1 0F F0" +
    //               "00 00 00 00 00 00 78 77 88 C1 00 00 00 00 00 00")
    //           .hexToUByteArray()
    //   private val validSector16 =
    //       ("D2 00 11 EE 12 ED 13 EC 14 EB 15 EA 16 E9 17 E8" +
    //               "18 E7 19 E6 1A E5 1B E4 1C E3 1D E2 1E E1 1F E0" +
    //               "20 DF 21 DE 22 DD 23 DC 24 DB 25 DA 26 D9 27 D8" +
    //               "00 00 00 00 00 00 78 77 88 C2 00 00 00 00 00 00")
    //           .hexToUByteArray()

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

    #[test]
    fn valid_mad_v1() {
        let mut tag = MockClassic1k {
            key: TEST_MAD_A_KEY,
            sector0: VALID_SECTOR_0,
        };
        let mad = MifareApplicationDirectory::read_from_tag(&mut tag, &DEFAULT_READ_KEY_PROVIDER)
            .unwrap();
        assert_eq!(MadVersion::V1, mad.mad_version)
    }

    //   /** Replaces byte at index in array with specified value. */
    //   private fun UByteArray.replaceIndex(index: Int, newValue: UByte): UByteArray =
    //       this.mapIndexed { i, oldValue -> if (index == i) newValue else oldValue }.toUByteArray()
    //
    //   /** Recalculates and replaces CRC value for MAD v1 sector. */
    //   private fun UByteArray.recalculateMadV1Crc(): UByteArray {
    //     require(this.size == 64)
    //     return this.replaceIndex(16, Crc8Mad.compute(this.sliceArray(17..47)))
    //   }
    //
    //   /** Recalculates and replaces CRC value for MAD v2 sector. */
    //   private fun UByteArray.recalculateMadV2Crc(): UByteArray {
    //     require(this.size == 64)
    //     return this.replaceIndex(0, Crc8Mad.compute(this.sliceArray(1..47)))
    //   }
    //
    //   /** Converts MADv1 sector into MADv2 sector by changing version bits. */
    //   private fun UByteArray.makeMadV2(): UByteArray {
    //     require(this.size == 64)
    //     require(this[57] == 0xC1u.toUByte())
    //     return this.replaceIndex(57, 0xC2u)
    //   }
    //
    //   private fun mockClassic1k(sector0: UByteArray): MifareClassic {
    //     val tag = mockk<MifareClassic>()
    //     every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
    //     every { tag.readBlock(0) } returns sector0.sliceArray(0..15)
    //     every { tag.readBlock(1) } returns sector0.sliceArray(16..31)
    //     every { tag.readBlock(2) } returns sector0.sliceArray(32..47)
    //     every { tag.readBlock(3) } returns sector0.sliceArray(48..63)
    //
    //     return tag
    //   }
    //
    //   private fun mockClassic4k(sector0: UByteArray, sector16: UByteArray): MifareClassic {
    //     val tag = mockk<MifareClassic>()
    //     every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
    //     every { tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA) } just runs
    //     every { tag.readBlock(0) } returns sector0.sliceArray(0..15)
    //     every { tag.readBlock(1) } returns sector0.sliceArray(16..31)
    //     every { tag.readBlock(2) } returns sector0.sliceArray(32..47)
    //     every { tag.readBlock(3) } returns sector0.sliceArray(48..63)
    //     every { tag.readBlock(64) } returns sector16.sliceArray(0..15)
    //     every { tag.readBlock(65) } returns sector16.sliceArray(16..31)
    //     every { tag.readBlock(66) } returns sector16.sliceArray(32..47)
    //     every { tag.readBlock(67) } returns sector16.sliceArray(48..63)
    //
    //     return tag
    //   }
    //
    //   @Test
    //   fun `unpersonalized card should fail`() {
    //     // When GPB is 0x69 it indicates an unpersonalized card.
    //     val tag = mockClassic1k(validSector0.replaceIndex(57, 0x69u))
    //     assertFailsWith<NotPersonalizedException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3) // Should start by reading block 3 to get GPB.
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `false mad DA bit should fail`() {
    //     // First bit of GPB is the DA bit.
    //     val tag = mockClassic1k(validSector0.replaceIndex(57, 0b01000001u))
    //     assertFailsWith<MadNotFoundException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3) // Should start by reading block 3 to get GPB.
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `multi-application bit should be read`() {
    //     // Second bit of GPB is the MA bit.
    //     // Check multi-application.
    //     val maTag = mockClassic1k(validSector0.replaceIndex(57, 0b11000001u))
    //     assertTrue(
    //         MifareApplicationDirectory.readFromMifareClassic(maTag, defaultReadKeyProvider)
    //             .multiApplicationCard,
    //         "Expected multi-application card")
    //
    //     verifySequence {
    //       maTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       maTag.readBlock(3)
    //       maTag.readBlock(1)
    //       maTag.readBlock(2)
    //     }
    //     confirmVerified(maTag)
    //
    //     // Check single-application.
    //     val saTag = mockClassic1k(validSector0.replaceIndex(57, 0b10000001u))
    //     assertFalse(
    //         MifareApplicationDirectory.readFromMifareClassic(saTag, defaultReadKeyProvider)
    //             .multiApplicationCard,
    //         "Expected single-application card")
    //
    //     verifySequence {
    //       saTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       saTag.readBlock(3)
    //       saTag.readBlock(1)
    //       saTag.readBlock(2)
    //     }
    //     confirmVerified(saTag)
    //   }
    //
    //   @Test
    //   fun `invalid mad version should fail`() {
    //     // Final two bits of GPB is the MAD version which must be 1 or 2.
    //     val tag1 = mockClassic1k(validSector0.replaceIndex(57, 0b11000000u))
    //     assertFailsWith<InvalidMadVersionException> {
    //       // 0b00 MAD version bits.
    //       MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag1.readBlock(3)
    //     }
    //     confirmVerified(tag1)
    //
    //     val tag2 = mockClassic1k(validSector0.replaceIndex(57, 0b11000011u))
    //     assertFailsWith<InvalidMadVersionException> {
    //       // 0b11 MAD version bits.
    //       MifareApplicationDirectory.readFromMifareClassic(tag2, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag2.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag2.readBlock(3)
    //     }
    //     confirmVerified(tag1)
    //   }
    //
    //   @Test
    //   fun `invalid mad v1 crc should fail`() {
    //     // 17th byte in sector 0 is CRC.
    //     val tag = mockClassic1k(validSector0.replaceIndex(16, 0u))
    //     assertFailsWith<InvalidMadCrcException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `check card publisher sector`() {
    //     // 18th byte in sector 0 is the info byte which contains the CPS pointer.
    //     // CRC must be recalculated when modifying info byte 17.
    //
    //     val nullCpsTag = mockClassic1k(validSector0.replaceIndex(17, 0u).recalculateMadV1Crc())
    //     assertNull(
    //         MifareApplicationDirectory.readFromMifareClassic(nullCpsTag, defaultReadKeyProvider)
    //             .cardPublisherSector)
    //
    //     verifySequence {
    //       nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       nullCpsTag.readBlock(3)
    //       nullCpsTag.readBlock(1)
    //       nullCpsTag.readBlock(2)
    //     }
    //     confirmVerified(nullCpsTag)
    //
    //     for (cps in 0x01u..0x0Fu) {
    //       val tag = mockClassic1k(validSector0.replaceIndex(17, cps.toUByte()).recalculateMadV1Crc())
    //       assertEquals(
    //           cps.toUByte(),
    //           MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //               .cardPublisherSector)
    //
    //       verifySequence {
    //         tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //         tag.readBlock(3)
    //         tag.readBlock(1)
    //         tag.readBlock(2)
    //       }
    //       confirmVerified(tag)
    //     }
    //   }
    //
    //   @Test
    //   fun `check invalid mad v1 card publisher sector`() {
    //     // CPS cannot point to sector 0x10 since that's reserved for MADv2.
    //     val tag1 = mockClassic1k(validSector0.replaceIndex(17, 0x10u).recalculateMadV1Crc())
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag1.readBlock(3)
    //       tag1.readBlock(1)
    //       tag1.readBlock(2)
    //     }
    //     confirmVerified(tag1)
    //
    //     // Mad V1 CPS cannot exceed 15.
    //     for (info in 0x10u..0x3Fu) {
    //       val tag = mockClassic1k(validSector0.replaceIndex(17, info.toUByte()).recalculateMadV1Crc())
    //       assertFailsWith<IllegalArgumentException> {
    //         MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //       }
    //     }
    //   }
    //
    //   @Test
    //   fun `valid mad v2 should decode`() {
    //     val tag = mockClassic4k(validSector0.makeMadV2(), validSector16)
    //
    //     val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //     assertEquals(2u, mad.madVersion)
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //       tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(64)
    //       tag.readBlock(65)
    //       tag.readBlock(66)
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `invalid mad v2 crc should fail`() {
    //     // Replace CRC with 0 for MADv2 sector.
    //     val tag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(0, 0u))
    //
    //     assertFailsWith<InvalidMadCrcException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //     }
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //       tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(64)
    //       tag.readBlock(65)
    //       tag.readBlock(66)
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `check valid mad v2 cps`() {
    //     // 2nd byte in sector 16 is the info byte which contains the CPS pointer.
    //
    //     val nullCpsTag =
    //         mockClassic4k(
    //             validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x0u).recalculateMadV2Crc())
    //     assertNull(
    //         MifareApplicationDirectory.readFromMifareClassic(nullCpsTag, defaultReadKeyProvider)
    //             .cardPublisherSector)
    //
    //     verifySequence {
    //       nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       nullCpsTag.readBlock(3)
    //       nullCpsTag.readBlock(1)
    //       nullCpsTag.readBlock(2)
    //       nullCpsTag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //       nullCpsTag.readBlock(64)
    //       nullCpsTag.readBlock(65)
    //       nullCpsTag.readBlock(66)
    //     }
    //     confirmVerified(nullCpsTag)
    //
    //     for (cps in 0x01u..0x027u) {
    //       // Skip MADv2 sector.
    //       if (cps == 0x10u) {
    //         continue
    //       }
    //
    //       val tag =
    //           mockClassic4k(
    //               validSector0.makeMadV2(),
    //               validSector16.replaceIndex(1, cps.toUByte()).recalculateMadV2Crc())
    //       assertEquals(
    //           cps.toUByte(),
    //           MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //               .cardPublisherSector)
    //
    //       verifySequence {
    //         tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //         tag.readBlock(3)
    //         tag.readBlock(1)
    //         tag.readBlock(2)
    //         tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //         tag.readBlock(64)
    //         tag.readBlock(65)
    //         tag.readBlock(66)
    //       }
    //       confirmVerified(nullCpsTag)
    //     }
    //   }
    //
    //   @Test
    //   fun `invalid mad v2 cps should fail`() {
    //     // 2nd byte in sector 16 is the info byte which contains the CPS pointer.
    //
    //     // CPS cannot point at MAD v2 sector 16 (0x10).
    //     val tag1 =
    //         mockClassic4k(
    //             validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x10u).recalculateMadV2Crc())
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    //     }
    //     verifySequence {
    //       tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag1.readBlock(3)
    //       tag1.readBlock(1)
    //       tag1.readBlock(2)
    //       tag1.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //       tag1.readBlock(64)
    //       tag1.readBlock(65)
    //       tag1.readBlock(66)
    //     }
    //     confirmVerified(tag1)
    //
    //     // CPS pointer cannot exceed sector 39.
    //     for (info in 0x28u..0x3Fu) {
    //       val tag =
    //           mockClassic4k(
    //               validSector0.makeMadV2(),
    //               validSector16.replaceIndex(1, info.toUByte()).recalculateMadV2Crc())
    //       assertFailsWith<IllegalArgumentException> {
    //         MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //       }
    //
    //       verifySequence {
    //         tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //         tag.readBlock(3)
    //         tag.readBlock(1)
    //         tag.readBlock(2)
    //         tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //         tag.readBlock(64)
    //         tag.readBlock(65)
    //         tag.readBlock(66)
    //       }
    //       confirmVerified(tag)
    //     }
    //   }
    //
    //   @Test
    //   fun `check valid mad v1 applications`() {
    //     val tag = mockClassic1k(validSector0)
    //
    //     val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //
    //     assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    //     for (sector in 1..13) {
    //       assertEquals(
    //           MadAid.fromAdministrationCode(MadAdministrationCode.FREE), mad.applications[sector])
    //     }
    //
    //     // Gallagher AIDs
    //     assertEquals(
    //         MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x11u),
    //         mad.applications[14])
    //     assertEquals(
    //         MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x12u),
    //         mad.applications[15])
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `check more valid mad v1 applications`() {
    //     val tag = mockClassic1k(validSector0MoreAids)
    //
    //     val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //
    //     assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    //     for (sector in 1..15) {
    //       assertEquals(
    //           MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
    //     }
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //     }
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `check valid mad v2 applications`() {
    //     val tag = mockClassic4k(validSector0MoreAids.makeMadV2(), validSector16)
    //
    //     val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    //
    //     assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
    //     for (sector in 1..39) {
    //       if (sector == 16) {
    //         continue // Skip MADv2 sector.
    //       }
    //       assertEquals(
    //           MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
    //     }
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(3)
    //       tag.readBlock(1)
    //       tag.readBlock(2)
    //       tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
    //       tag.readBlock(64)
    //       tag.readBlock(65)
    //       tag.readBlock(66)
    //     }
    //
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `check create mad`() {
    //     MifareApplicationDirectory.create(true, 1u, null, mapOf())
    //     MifareApplicationDirectory.create(false, 1u, null, mapOf())
    //     MifareApplicationDirectory.create(true, 2u, null, mapOf())
    //     MifareApplicationDirectory.create(false, 2u, null, mapOf())
    //
    //     for (cps in 1u..15u) {
    //       MifareApplicationDirectory.create(true, 1u, cps.toUByte(), mapOf())
    //       MifareApplicationDirectory.create(false, 1u, cps.toUByte(), mapOf())
    //     }
    //
    //     for (cps in 1u..39u) {
    //       if (cps == 16u) {
    //         continue // Skip MADv2 sector
    //       }
    //       MifareApplicationDirectory.create(true, 2u, cps.toUByte(), mapOf())
    //       MifareApplicationDirectory.create(false, 2u, cps.toUByte(), mapOf())
    //     }
    //   }
    //
    //   @Test
    //   fun `check create mad v1 with apps`() {
    //     for (sector in 1..15) {
    //       val mad =
    //           MifareApplicationDirectory.create(
    //               true,
    //               1u,
    //               null,
    //               mapOf(
    //                   sector to
    //                       MadAid.fromRaw(
    //                           sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs
    //                   ))
    //       assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    //     }
    //
    //     val madFull =
    //         MifareApplicationDirectory.create(
    //             true,
    //             1u,
    //             null,
    //             (1..15).associateWith { s -> MadAid.fromRaw(s.toUByte().inv(), s.toUByte()) })
    //
    //     assertEquals(15, madFull.applications.size, "Expected 15 MADv1 sector AIDs.")
    //     for (sector in 1..15) {
    //       assertEquals(sector.toUByte(), madFull.applications[sector]!!.applicationCode)
    //     }
    //   }
    //
    //   @Test
    //   fun `check create mad v2 with apps`() {
    //     for (sector in 1..39) {
    //       if (sector == 16) {
    //         continue // Skip MADv2 sector
    //       }
    //       val mad =
    //           MifareApplicationDirectory.create(
    //               true,
    //               2u,
    //               null,
    //               mapOf(
    //                   sector to
    //                       MadAid.fromRaw(
    //                           sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs.
    //                   ))
    //       assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
    //     }
    //
    //     val madFull =
    //         MifareApplicationDirectory.create(
    //             true,
    //             2u,
    //             null,
    //             (1..39)
    //                 .filter { s -> s != 16 } // Skip MADv2 sector.
    //                 .associateWith { s -> MadAid.fromRaw(s.toUByte().inv(), s.toUByte()) })
    //     assertEquals(38, madFull.applications.size, "Expected 38 MADv2 sector AIDs.")
    //     for (sector in 1..39) {
    //       if (sector == 16) {
    //         continue // Skip MADv2 sector 16.
    //       }
    //       assertEquals(sector.toUByte(), madFull.applications[sector]!!.applicationCode)
    //     }
    //   }
    //
    //   @Test
    //   fun `check create invalid mad version`() {
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 0u, null, mapOf())
    //     }
    //
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 3u, null, mapOf())
    //     }
    //   }
    //
    //   @Test
    //   fun `check create invalid mad cps`() {
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 1u, 0u, mapOf())
    //     }
    //
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 2u, 0u, mapOf())
    //     }
    //
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 1u, 16u, mapOf())
    //     }
    //
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(true, 2u, 40u, mapOf())
    //     }
    //   }
    //
    //   @Test
    //   fun `check create mad v1 with invalid apps`() {
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(
    //           true, 1u, null, mapOf(0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    //     }
    //
    //     for (sector in 16..100) {
    //       assertFailsWith<IllegalArgumentException> {
    //         MifareApplicationDirectory.create(
    //             true, 1u, null, mapOf(sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    //       }
    //     }
    //   }
    //
    //   @Test
    //   fun `check create mad v2 with invalid apps`() {
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(
    //           true, 2u, null, mapOf(0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    //     }
    //
    //     assertFailsWith<IllegalArgumentException> {
    //       MifareApplicationDirectory.create(
    //           true, 2u, null, mapOf(16 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    //     }
    //
    //     for (sector in 40..100) {
    //       assertFailsWith<IllegalArgumentException> {
    //         MifareApplicationDirectory.create(
    //             true, 1u, null, mapOf(sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    //       }
    //     }
    //   }
    //
    //   @Test
    //   fun `check mad v1 apps are filled`() {
    //     val mad = MifareApplicationDirectory.create(true, 1u, null, mapOf())
    //     assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs")
    //     assertTrue(
    //         mad.applications.all { (_, aid) ->
    //           aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
    //         },
    //         "Expected all empty apps to be filled with FREE")
    //   }
    //
    //   @Test
    //   fun `check mad v2 apps are filled`() {
    //     val mad = MifareApplicationDirectory.create(true, 2u, null, mapOf())
    //     assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs")
    //     assertTrue(
    //         mad.applications.all { (_, aid) ->
    //           aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
    //         },
    //         "Expected all empty apps to be filled with FREE")
    //   }
    //
    //   @Test
    //   fun `mad v1 should write correctly`() {
    //     val mad =
    //         MifareApplicationDirectory.create(
    //             true,
    //             1u,
    //             null,
    //             mapOf(
    //                 14 to MadAid.fromRaw(0x4811u),
    //                 15 to MadAid.fromRaw(0x4812u),
    //             ))
    //
    //     val tag = mockk<MifareClassic>()
    //     every { tag.authenticateSector(any(), any(), any()) } just runs
    //     every { tag.writeBlock(any(), any()) } just runs
    //
    //     mad.writeToMifareClassic(tag, defaultWriteKeyProvider)
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyB, MifareKeyType.KeyB)
    //       tag.writeBlock(1, validSector0.sliceArray(16..31))
    //       tag.writeBlock(2, validSector0.sliceArray(32..47))
    //       tag.writeBlock(
    //           3,
    //           ubyteArrayOf(
    //               0xA0u,
    //               0xA1u,
    //               0xA2u,
    //               0xA3u,
    //               0xA4u,
    //               0xA5u,
    //               0x78u,
    //               0x77u,
    //               0x88u,
    //               0xC1u,
    //               0xB0u,
    //               0xB1u,
    //               0xB2u,
    //               0xB3u,
    //               0xB4u,
    //               0xB5u))
    //     }
    //
    //     confirmVerified(tag)
    //   }
    //
    //   @Test
    //   fun `mad v2 should write correctly`() {
    //     val mad =
    //         MifareApplicationDirectory.create(
    //             true,
    //             2u,
    //             null,
    //             (1..39)
    //                 .filter { it != 16 }
    //                 .associateWith { MadAid.fromRaw(it.toUByte().inv(), it.toUByte()) })
    //
    //     val tag = mockk<MifareClassic>()
    //     every { tag.authenticateSector(any(), any(), any()) } just runs
    //     every { tag.writeBlock(any(), any()) } just runs
    //
    //     mad.writeToMifareClassic(tag, defaultWriteKeyProvider)
    //
    //     verifySequence {
    //       tag.authenticateSector(0, madKeyB, MifareKeyType.KeyB)
    //       tag.writeBlock(1, validSector0MoreAids.sliceArray(16..31))
    //       tag.writeBlock(2, validSector0MoreAids.sliceArray(32..47))
    //       tag.writeBlock(
    //           3,
    //           ubyteArrayOf(
    //               0xA0u,
    //               0xA1u,
    //               0xA2u,
    //               0xA3u,
    //               0xA4u,
    //               0xA5u,
    //               0x78u,
    //               0x77u,
    //               0x88u,
    //               0xC2u,
    //               0xB0u,
    //               0xB1u,
    //               0xB2u,
    //               0xB3u,
    //               0xB4u,
    //               0xB5u))
    //       tag.authenticateSector(16, madKeyB, MifareKeyType.KeyB)
    //       tag.writeBlock(MifareClassic.sectorToBlock(16, 0), validSector16.sliceArray(0..15))
    //       tag.writeBlock(MifareClassic.sectorToBlock(16, 1), validSector16.sliceArray(16..31))
    //       tag.writeBlock(MifareClassic.sectorToBlock(16, 2), validSector16.sliceArray(32..47))
    //       tag.writeBlock(
    //           MifareClassic.sectorToBlock(16, 3),
    //           ubyteArrayOf(
    //               0xA0u,
    //               0xA1u,
    //               0xA2u,
    //               0xA3u,
    //               0xA4u,
    //               0xA5u,
    //               0x78u,
    //               0x77u,
    //               0x88u,
    //               0xC2u,
    //               0xB0u,
    //               0xB1u,
    //               0xB2u,
    //               0xB3u,
    //               0xB4u,
    //               0xB5u))
    //     }
    //
    //     confirmVerified(tag)
    //   }
}
