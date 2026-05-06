/// Gallagher Card Application Directory (CAD) for MIFARE Classic.
///
/// Based on: https://github.com/megabug/gallagher-research/blob/master/formats/cad.md
use heapless::LinearMap;

use crate::mifare::classic::{FourBlockOffset, FourBlockSector, KeyProvider, Tag};

use super::Error;

/// Max number of credential mappings in a CAD sector.
const MAX_CAD_MAPPINGS: usize = 12;

/// (region_code, facility_code) -> sector number
pub type CadMappings = LinearMap<(u8, u16), u8, MAX_CAD_MAPPINGS>;

pub struct CardApplicationDirectory {
    pub mappings: CadMappings,
}

impl CardApplicationDirectory {
    /// Key A for CAD sector — same as MAD key.
    pub const KEY_A: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    /// Key B for CAD sector — same as MAD key.
    pub const KEY_B: [u8; 6] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    /// Access bits: Key A read, Key B read/write all blocks.
    pub const ACCESS_BITS: [u8; 3] = [0x78, 0x77, 0x88];

    pub fn new(mappings: impl IntoIterator<Item = ((u8, u16), u8)>) -> Self {
        Self { mappings: mappings.into_iter().collect() }
    }

    pub(crate) fn from_bytes(data: &[u8; 48], sector_hint: u8) -> Result<Self, Error> {
        let expected_crc = ((data[0] as u16) << 8) | (data[1] as u16);
        if crc16(&data[2..]) != expected_crc {
            return Err(Error::InvalidCadCrc(sector_hint));
        }
        // Bytes 2-3: unknown header (skip).
        // Bytes 4-45: 12 × 28-bit mappings = 42 bytes.
        let raw_mappings = unpack_28bit_groups(&data[4..46]);
        let mut mappings = CadMappings::new();
        for raw in &raw_mappings {
            if *raw == 0 {
                break; // Sector 0 signals end-of-list.
            }
            let region_code = ((raw & 0xF000000) >> 24) as u8;
            let facility_code = ((raw & 0xFFFF00) >> 8) as u16;
            let cred_sector = (raw & 0xFF) as u8;
            let _ = mappings.insert((region_code, facility_code), cred_sector);
        }
        Ok(Self { mappings })
    }

    pub(crate) fn to_bytes(&self) -> [u8; 48] {
        let mut raw_mappings = [0u32; MAX_CAD_MAPPINGS];
        for (i, ((region_code, facility_code), cred_sector)) in self.mappings.iter().enumerate() {
            raw_mappings[i] = ((*region_code as u32) << 24)
                | ((*facility_code as u32) << 8)
                | (*cred_sector as u32);
        }
        let mapping_bytes = pack_28bit_groups(&raw_mappings);

        // Layout for bytes 2-47 (= data CRC is computed over):
        //   [0x00, 0x01]  — unknown header seen in the field
        //   mapping_bytes — 42 bytes (12 × 28 bits)
        //   [0x00, 0x00]  — padding to fill 3 blocks
        let mut crc_input = [0u8; 46];
        crc_input[1] = 0x01;
        crc_input[2..44].copy_from_slice(&mapping_bytes);
        let crc = crc16(&crc_input);

        let mut result = [0u8; 48];
        result[0] = (crc >> 8) as u8;
        result[1] = crc as u8;
        result[2..48].copy_from_slice(&crc_input);
        result
    }

    pub fn read_from_tag<T: Tag>(
        tag: &mut T,
        sector: FourBlockSector,
        key_provider: &impl KeyProvider,
    ) -> Result<Self, Error> {
        key_provider.authenticate(tag, sector.into())?;

        // Read the 3 data blocks (block 3 is the sector trailer, not read).
        let b0 = tag.read_block(sector.block(FourBlockOffset::B0))?;
        let b1 = tag.read_block(sector.block(FourBlockOffset::B1))?;
        let b2 = tag.read_block(sector.block(FourBlockOffset::B2))?;

        // Assemble the 48 bytes and parse.
        let mut sector_data = [0u8; 48];
        sector_data[0..16].copy_from_slice(&b0);
        sector_data[16..32].copy_from_slice(&b1);
        sector_data[32..48].copy_from_slice(&b2);

        Self::from_bytes(&sector_data, sector as u8)
    }

    pub fn write_to_tag<T: Tag>(
        &self,
        tag: &mut T,
        sector: FourBlockSector,
        key_provider: &impl KeyProvider,
    ) -> Result<(), Error> {
        key_provider.authenticate(tag, sector.into())?;

        let data_bytes = self.to_bytes();

        // Assemble full 64 bytes (4 blocks).
        let mut data = [0u8; 64];
        data[0..48].copy_from_slice(&data_bytes);

        // Block 3 is the sector trailer.
        data[48..54].copy_from_slice(&Self::KEY_A);
        data[54..57].copy_from_slice(&Self::ACCESS_BITS);
        // data[57] = 0x00 (GPB, already zero)
        data[58..64].copy_from_slice(&Self::KEY_B);

        let block0: [u8; 16] = data[0..16].try_into().unwrap();
        let block1: [u8; 16] = data[16..32].try_into().unwrap();
        let block2: [u8; 16] = data[32..48].try_into().unwrap();
        let block3: [u8; 16] = data[48..64].try_into().unwrap();

        tag.write_block(sector.block(FourBlockOffset::B0), block0)?;
        tag.write_block(sector.block(FourBlockOffset::B1), block1)?;
        tag.write_block(sector.block(FourBlockOffset::B2), block2)?;
        tag.write_block(sector.block(FourBlockOffset::B3), block3)?;

        Ok(())
    }
}

/// Unpack 12 × 28-bit groups from a byte slice (MSB first).
fn unpack_28bit_groups(data: &[u8]) -> [u32; 12] {
    let mut groups = [0u32; 12];
    for (g, group) in groups.iter_mut().enumerate() {
        let bit_offset = g * 28;
        let mut value = 0u32;
        for b in 0..28 {
            let i = bit_offset + b;
            let byte = data[i / 8];
            let bit = (byte >> (7 - (i % 8))) & 1;
            value = (value << 1) | (bit as u32);
        }
        *group = value;
    }
    groups
}

/// Pack 12 × 28-bit groups into bytes (MSB first), producing 42 bytes.
fn pack_28bit_groups(groups: &[u32; 12]) -> [u8; 42] {
    let mut data = [0u8; 42];
    for (g, &value) in groups.iter().enumerate() {
        let bit_offset = g * 28;
        for b in 0..28 {
            let i = bit_offset + b;
            let bit = ((value >> (27 - b)) & 1) as u8;
            data[i / 8] |= bit << (7 - (i % 8));
        }
    }
    data
}

/// CRC-16 as used by Gallagher CAD.
///
/// Polynomial 0x1021, init 0xFFFF, LSB-first processing.
fn crc16(data: &[u8]) -> u16 {
    const POLY: u32 = 0x1021;
    let mut crc: u32 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    (crc & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        // Values must be <= 28 bits (max 0x0FFF_FFFF).
        let groups: [u32; 12] = [
            0x0112_3405,
            0x0256_7807,
            0x039A_BC09,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let packed = pack_28bit_groups(&groups);
        let unpacked = unpack_28bit_groups(&packed);
        assert_eq!(groups, unpacked);
    }

    #[test]
    fn pack_unpack_all_ones() {
        let groups = [0x0FFF_FFFFu32; 12];
        let packed = pack_28bit_groups(&groups);
        let unpacked = unpack_28bit_groups(&packed);
        assert_eq!(groups, unpacked);
    }

    #[test]
    fn pack_unpack_zero() {
        let groups = [0u32; 12];
        let packed = pack_28bit_groups(&groups);
        let unpacked = unpack_28bit_groups(&packed);
        assert_eq!(groups, unpacked);
    }

    #[test]
    fn crc16_known_vectors() {
        // From Kotlin Crc16CadTest — vectors sourced from megabug/gallagher-research.
        assert_eq!(crc16(&[0x00]), 0x127B);

        // Real card sector (bytes 2-47 of a known valid CAD sector).
        let v = [0x00u8, 0x01, 0xC1, 0x33, 0x70, 0xFD, 0x13, 0x38, 0x0D,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(crc16(&v), 0x1B58);
        assert_eq!(crc16(&[0x00, 0x01, 0x00, 0x0D, 0xE0, 0xF0,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0x108E);
        // Duplicate of v (from Kotlin test — two copies of the same real-card vector).
        assert_eq!(crc16(&v), 0x1B58);
        assert_eq!(crc16(&[0xBA, 0x7B, 0xA7, 0x93, 0x3C, 0x8C, 0x02, 0x76, 0xC0, 0x1C,
                            0xAF, 0x92, 0x44, 0xCB, 0x96, 0x59, 0x5E, 0x6B, 0xF3, 0xA1,
                            0x63, 0xEB, 0xFB, 0x17, 0x82, 0x96, 0xD8, 0xBE, 0xAE, 0xD9,
                            0xFF, 0x15, 0x5D, 0xD0, 0x43, 0xA9, 0xF3, 0xEC, 0x0B, 0x76,
                            0xE9, 0xC5, 0x40, 0x2A, 0x0C, 0x8D]), 0x199E);
        assert_eq!(crc16(&[0x99, 0x08, 0x8C, 0x9E, 0xEA, 0xAE, 0x70, 0xB7, 0x19, 0xCE,
                            0x69, 0x16, 0x23, 0x1D, 0x53, 0x3D, 0xB6, 0x04, 0xEC, 0xF3,
                            0x02, 0x8A, 0xFE, 0x97, 0xB9, 0x21, 0x23, 0xA1, 0xD1, 0x2E,
                            0x5F, 0x98, 0x35, 0xB9, 0xDF, 0x70, 0xEB, 0x01, 0x79, 0x5C,
                            0xE6, 0xDD, 0x44, 0x5A, 0x47, 0x97]), 0x0976);
        assert_eq!(crc16(&[0xA1, 0xD5, 0xC8, 0x06, 0xCE, 0xE8, 0xE1, 0x10, 0x36, 0xFD,
                            0x54, 0x9A, 0x45, 0x6C, 0xCC, 0x02, 0x9B, 0x15, 0xA6, 0xE6,
                            0x1D, 0x0F, 0xF6, 0x44, 0xEB, 0x59, 0x03, 0x3C, 0x47, 0x57,
                            0x14, 0xA9, 0x7C, 0x88, 0x0A, 0x54, 0x4F, 0x96, 0x83, 0x78,
                            0x46, 0x5A, 0xB7, 0xDC, 0x4C, 0xBF]), 0x1E40);
        assert_eq!(crc16(&[0x03, 0xB4, 0xED, 0xEA, 0x8B, 0x71, 0xFD, 0x44, 0x56, 0x40,
                            0xAD, 0xF4, 0xB6, 0xB4, 0xF5, 0xDC, 0x0C, 0x04, 0xBD, 0x5D,
                            0x7B, 0x81, 0x0A, 0x0A, 0x3D, 0x73, 0xAF, 0xEF, 0xD6, 0x60,
                            0xCF, 0xFA, 0x86, 0x17, 0xFE, 0x65, 0x80, 0x20, 0xF4, 0x58,
                            0x25, 0x7B, 0xDD, 0x29, 0x53, 0x65]), 0x036E);
        assert_eq!(crc16(&[0xF8, 0xC5, 0x75, 0x36, 0x3A, 0x5E, 0x31, 0x84, 0xFE, 0x9B,
                            0x93, 0x39, 0x0D, 0x11, 0x7B, 0x02, 0xC9, 0x09, 0xFE, 0x63,
                            0x58, 0x24, 0x07, 0x33, 0x83, 0xFE, 0x7E, 0x2D, 0xCE, 0xD4,
                            0xC8, 0x50, 0x07, 0x44, 0x8E, 0xA6, 0xB1, 0x72, 0x05, 0x81,
                            0x7D, 0xE9, 0xCA, 0x3F, 0xAF, 0xE9]), 0x026D);
        assert_eq!(crc16(&[0xD9, 0x5C, 0xCF, 0x5C, 0x58, 0x2F, 0x4D, 0x2D, 0xF7, 0xC9,
                            0xE3, 0x8E, 0x0E, 0xA0, 0x3E, 0x3B, 0x3B, 0x9F, 0x8B, 0x9C,
                            0x55, 0x13, 0xC2, 0xF0, 0x76, 0xA1, 0x54, 0x96, 0x53, 0x04,
                            0xF6, 0xF9, 0x78, 0xAF, 0x7A, 0x9E, 0xE9, 0x3D, 0x3F, 0xBF,
                            0x69, 0xA3, 0x2B, 0x0C, 0x4B, 0x81]), 0x1B6C);
        assert_eq!(crc16(&[0xE9, 0xA3, 0xCD, 0x12, 0xED, 0x2F, 0x80, 0x0C, 0x2C, 0x76,
                            0x52, 0x0A, 0x34, 0x65, 0xFC, 0x3F, 0xF7, 0xC3, 0x3E, 0xA5,
                            0xEB, 0xDE, 0x1B, 0x7D, 0xEE, 0x84, 0x8F, 0xC6, 0x3E, 0x6D,
                            0xA6, 0x28, 0x3C, 0x92, 0x57, 0xF8, 0xFF, 0xA0, 0x82, 0x15,
                            0x11, 0x59, 0x61, 0x6B, 0x2D, 0xD4]), 0x1DE0);
        assert_eq!(crc16(&[0x60, 0xE1, 0x02, 0x3B, 0xAC, 0x65, 0x5E, 0xAD, 0x01, 0x77,
                            0x24, 0xA8, 0x96, 0x9A, 0xCD, 0x0D, 0xA2, 0x8A, 0x14, 0xFC,
                            0x4B, 0x23, 0x07, 0xE5, 0x4A, 0x16, 0xD0, 0x64, 0x52, 0xFF,
                            0x10, 0x4E, 0x96, 0x70, 0x08, 0xC4, 0x6C, 0xF8, 0x84, 0xCD,
                            0xFC, 0x8C, 0xB6, 0xB4, 0x10, 0xE1]), 0x04E2);
        assert_eq!(crc16(&[0x20, 0x08, 0x47, 0x8A, 0x53, 0x20, 0x49, 0x29, 0x50, 0xA9,
                            0x62, 0x57, 0x17, 0x16, 0x67, 0x89, 0xC4, 0x37, 0xB0, 0x96,
                            0x45, 0x63, 0x42, 0xC8, 0xCD, 0xEB, 0xCE, 0x00, 0x71, 0x26,
                            0xFA, 0xDD, 0xF2, 0x3F, 0xE4, 0xB3, 0x5C, 0xD6, 0x55, 0x71,
                            0x7C, 0x8A, 0xEC, 0x06, 0x37, 0x90]), 0x0880);
        assert_eq!(crc16(&[0x9D, 0xB8, 0x41, 0x10, 0x53, 0x42, 0x4B, 0xAA, 0xDD, 0x3C,
                            0x67, 0x21, 0x22, 0xA1, 0xD7, 0x1D, 0xFB, 0x17, 0x10, 0x2F,
                            0x47, 0x11, 0x04, 0x37, 0x3B, 0xDB, 0x41, 0x9D, 0x71, 0xB9,
                            0xCA, 0x4D, 0xC3, 0x2F, 0xE0, 0x52, 0xC4, 0xF1, 0x2B, 0xBA,
                            0x5F, 0xE4, 0xCF, 0xB6, 0x0A, 0xDB]), 0x064A);
    }

    #[test]
    fn from_bytes_valid_real_world_sector() {
        // First 48 bytes of validCadSector from Kotlin CardApplicationDirectoryTest.
        // Bytes 0-1: CRC 0x1B58; bytes 2-3: header; bytes 4-45: two mappings then zeros.
        let data: [u8; 48] = [
            0x1B, 0x58, 0x00, 0x01, 0xC1, 0x33, 0x70, 0xFD, 0x13, 0x38, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let cad = CardApplicationDirectory::from_bytes(&data, 0).unwrap();
        // group[0] = 0x0C13370F → region=12, facility=4919, sector=15
        // group[1] = 0x0D13380D → region=13, facility=4920, sector=13
        // group[2] = 0 → end of list
        assert_eq!(cad.mappings.len(), 2);
        assert_eq!(cad.mappings.get(&(12, 4919)), Some(&15));
        assert_eq!(cad.mappings.get(&(13, 4920)), Some(&13));
    }

    #[test]
    fn from_bytes_bad_crc_is_rejected() {
        let mut data: [u8; 48] = [
            0x1B, 0x58, 0x00, 0x01, 0xC1, 0x33, 0x70, 0xFD, 0x13, 0x38, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data[4] ^= 0xFF; // corrupt first mapping byte
        assert!(matches!(
            CardApplicationDirectory::from_bytes(&data, 5),
            Err(super::Error::InvalidCadCrc(5))
        ));
    }

    #[test]
    fn encode_decode_roundtrip_cad() {
        let cad = CardApplicationDirectory::new([((2u8, 1337u16), 5u8), ((3u8, 500u16), 7u8)]);
        let bytes = cad.to_bytes();
        let decoded = CardApplicationDirectory::from_bytes(&bytes, 0).unwrap();
        assert_eq!(decoded.mappings.len(), 2);
        assert_eq!(decoded.mappings.get(&(2, 1337)), Some(&5));
        assert_eq!(decoded.mappings.get(&(3, 500)), Some(&7));
    }

    #[test]
    fn encode_decode_roundtrip_cad_empty() {
        let cad = CardApplicationDirectory::new([]);
        let bytes = cad.to_bytes();
        let decoded = CardApplicationDirectory::from_bytes(&bytes, 0).unwrap();
        assert_eq!(decoded.mappings.len(), 0);
    }
}
