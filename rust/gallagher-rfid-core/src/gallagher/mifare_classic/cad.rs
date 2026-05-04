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

        // Assemble the 48 bytes.
        let mut sector_data = [0u8; 48];
        sector_data[0..16].copy_from_slice(&b0);
        sector_data[16..32].copy_from_slice(&b1);
        sector_data[32..48].copy_from_slice(&b2);

        // First two bytes are CRC (big-endian), rest is data.
        let expected_crc = ((sector_data[0] as u16) << 8) | (sector_data[1] as u16);
        let data = &sector_data[2..]; // 46 bytes

        if crc16(data) != expected_crc {
            return Err(Error::InvalidCadCrc(sector as u8));
        }

        // Bytes 2-3 of sector_data (bytes 0-1 of data) are an unknown header — skip them.
        // Bytes 4-45 of sector_data (bytes 2-43 of data) hold 12 × 28-bit mappings = 336 bits = 42 bytes.
        let mapping_bytes = &data[2..44];
        let raw_mappings = unpack_28bit_groups(mapping_bytes);

        let mut mappings = CadMappings::new();
        for raw in &raw_mappings {
            if *raw == 0 {
                break; // Sector 0 signals end-of-list.
            }
            let region_code = ((raw & 0xF000000) >> 24) as u8;
            let facility_code = ((raw & 0xFFFF00) >> 8) as u16;
            let cred_sector = (raw & 0xFF) as u8;
            // Ignore if map is full (shouldn't happen with valid CAD data).
            let _ = mappings.insert((region_code, facility_code), cred_sector);
        }

        Ok(Self { mappings })
    }

    pub fn write_to_tag<T: Tag>(
        &self,
        tag: &mut T,
        sector: FourBlockSector,
        key_provider: &impl KeyProvider,
    ) -> Result<(), Error> {
        key_provider.authenticate(tag, sector.into())?;

        // Pack mappings into 12 × 28-bit groups.
        let mut raw_mappings = [0u32; MAX_CAD_MAPPINGS];
        for (i, ((region_code, facility_code), cred_sector)) in self.mappings.iter().enumerate() {
            raw_mappings[i] = ((*region_code as u32) << 24)
                | ((*facility_code as u32) << 8)
                | (*cred_sector as u32);
        }
        let mapping_bytes = pack_28bit_groups(&raw_mappings);

        // Layout for bytes 2-47 of the sector (= data CRC is computed over):
        //   [0x00, 0x01]   — Unknown 2 bytes; seen like this in the field as per megabug field research
        //   mapping_bytes  — 42 bytes (12 × 28 bits)
        //   [0x00, 0x00]   — 2 bytes padding to fill 3 blocks
        let mut crc_input = [0u8; 46];
        crc_input[1] = 0x01;
        crc_input[2..44].copy_from_slice(&mapping_bytes);
        let crc = crc16(&crc_input);

        // Assemble full 64 bytes (4 blocks).
        let mut data = [0u8; 64];
        data[0] = (crc >> 8) as u8;
        data[1] = crc as u8;
        data[2..48].copy_from_slice(&crc_input);

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
}
