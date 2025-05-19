use std::{string::String};

/// Represents a valid MIFARE Classic sector from 0 to 39.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MifareClassicSector(u8);

/// Converts a `MifareClassicSector` into a u8 sector address.
impl From<MifareClassicSector> for u8 {
    fn from(value: MifareClassicSector) -> Self {
        value.0
    }
}

/// Converts a sector into its starting block address.
///
/// Sector-to-block mapping:
/// - Sectors 0–31 -> Blocks 0-124 (4 blocks per sector)
/// - Sectors 32–39 -> Blocks 128-240 (16 blocks per sector)
impl From<MifareClassicSector> for MifareClassicBlock {
    fn from(value: MifareClassicSector) -> Self {
        let sector = value.0;
        match sector {
            0..=31 => MifareClassicBlock(sector * 4),
            32..=39 => MifareClassicBlock(((sector - 32) * 16) + 128),
            // It should not be possible to create a `MifareClassicSector` of more than 39.
            _ => unreachable!("Out of bounds Mifare Classic Sector.")
        }
    }
}

/// Represents a valid MIFARE Classic block from 0 to 255.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MifareClassicBlock(u8);

/// Converts a `MifareClassicBlock` into a u8 block address.
impl From<MifareClassicBlock> for u8 {
    fn from(value: MifareClassicBlock) -> Self {
        value.0
    }
}

/// Converts a block address into its corresponding sector.
///
/// Block-to-sector mapping:
/// - Blocks 0–127 -> Sectors 0–31 (4 blocks per sector)
/// - Blocks 128–255 -> Sectors 32–39 (16 blocks per sector)
impl From<MifareClassicBlock> for MifareClassicSector {
    fn from(value: MifareClassicBlock) -> Self {
        let block = value.0;
        match block {
            0..=127 => MifareClassicSector(block / 4),
            _ => MifareClassicSector(((block - 128) / 16) + 32)
        }
    }
}

/// Represents which MIFARE Classic key to use for authentication.
#[derive(Debug, Clone, Copy)]
pub enum MifareClassicKeyType {
    KeyA,
    KeyB,
}

/// Trait defining basic operations for interacting with MIFARE Classic tags.
pub trait MifareClassic {
    /// Authenticate to a specific sector on the tag using Key A or B.
    fn authenticate(
        &mut self,
        sector: u8,
        key: [u8; 6],
        key_type: MifareClassicKeyType,
    ) -> Result<(), MifareClassicError>;

    /// Reads a 16-byte data block from the tag.
    fn read_block(&mut self, block: MifareClassicBlock) -> Result<[u8; 16], MifareClassicError>;

    /// Writes a 16-byte data block to the tag.
    fn write_block(&mut self, block: MifareClassicBlock, data: [u8; 16]) -> Result<(), MifareClassicError>;
}

/// Represents errors that can occur during MIFARE Classic operations.
#[derive(Debug)]
pub enum MifareClassicError {
    /// Failed to authenticate to a block.
    AuthenticationFailed {
        block: u8,
        reason: String,
    },

    /// Low-level PCSC or transport error.
    TransportError(String),
}

/// Trait for providing authentication to MIFARE Classic sectors.
///
/// Used to abstract how keys are retrieved and applied for authentication.
pub trait MifareClassicKeyProvider {
  fn authenticate<T: MifareClassic>(tag: T, sector: MifareClassicSector);
}