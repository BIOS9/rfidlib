use core::fmt;
use std::{string::String};

/// Represents a valid MIFARE Classic sector from 0 to 39.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MifareClassicSector(u8);

impl fmt::Display for MifareClassicSector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sector {}", self.0)
    }
}

/// Converts a `MifareClassicSector` into a `u8` sector address.
impl From<MifareClassicSector> for u8 {
    fn from(value: MifareClassicSector) -> Self {
        value.0
    }
}

/// Attempts conversion of a `u8` into a `MifareClassicSector`.
/// 
/// Valid values for a sector are 0..=39
impl TryFrom<u8> for MifareClassicSector {
    type Error = MifareClassicError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=39 => Ok(MifareClassicSector(value)),
            _ => Err(MifareClassicError::InvalidSector(value))
        }
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

impl fmt::Display for MifareClassicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Block {}", self.0)
    }
}

/// Converts a `u8` into a `MifareClassicBlock`.
/// 
/// Note: All `u8` values are valid since there are 256 blocks starting from 0 in MIFARE Classic.
impl From<u8> for MifareClassicBlock {
    fn from(value: u8) -> Self {
        MifareClassicBlock(value)
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
    /// Failed to authenticate to a sector.
    AuthenticationFailed {
        block: u8
    },

    /// Invalid value for a MIFARE classic sector.
    InvalidSector(u8),

    /// Low-level PCSC or transport error.
    TransportError(String),
}

/// Trait for providing authentication to MIFARE Classic sectors.
///
/// Used to abstract how keys are retrieved and applied for authentication.
pub trait MifareClassicKeyProvider {
  fn authenticate<T: MifareClassic>(tag: T, sector: MifareClassicSector);
}

#[test]
fn block_to_sector(){
    // 1k sectors
    assert_eq!(0u8, MifareClassicSector::from(MifareClassicBlock::from(0)).into());
    assert_eq!(0u8, MifareClassicSector::from(MifareClassicBlock::from(1)).into());
    assert_eq!(0u8, MifareClassicSector::from(MifareClassicBlock::from(2)).into());
    assert_eq!(0u8, MifareClassicSector::from(MifareClassicBlock::from(3)).into());
    assert_eq!(1u8, MifareClassicSector::from(MifareClassicBlock::from(4)).into());
    assert_eq!(1u8, MifareClassicSector::from(MifareClassicBlock::from(5)).into());
    assert_eq!(1u8, MifareClassicSector::from(MifareClassicBlock::from(6)).into());
    assert_eq!(1u8, MifareClassicSector::from(MifareClassicBlock::from(7)).into());
    assert_eq!(15u8, MifareClassicSector::from(MifareClassicBlock::from(60)).into());
    assert_eq!(15u8, MifareClassicSector::from(MifareClassicBlock::from(61)).into());
    assert_eq!(15u8, MifareClassicSector::from(MifareClassicBlock::from(62)).into());
    assert_eq!(15u8, MifareClassicSector::from(MifareClassicBlock::from(63)).into());

    // 4k sectors
    assert_eq!(31u8, MifareClassicSector::from(MifareClassicBlock::from(124)).into());
    assert_eq!(31u8, MifareClassicSector::from(MifareClassicBlock::from(125)).into());
    assert_eq!(31u8, MifareClassicSector::from(MifareClassicBlock::from(126)).into());
    assert_eq!(31u8, MifareClassicSector::from(MifareClassicBlock::from(127)).into());
    for b in 128..=143 {
      assert_eq!(32u8, MifareClassicSector::from(MifareClassicBlock::from(b)).into())
    }
    assert_eq!(33u8, MifareClassicSector::from(MifareClassicBlock::from(144)).into());
    assert_eq!(38u8, MifareClassicSector::from(MifareClassicBlock::from(239)).into());
    for b in 240..=255 {
      assert_eq!(39u8, MifareClassicSector::from(MifareClassicBlock::from(b)).into());
    }

    for b in 0..=255 {
        // Just making sure it doesnt panic.
        _ = MifareClassicSector::from(MifareClassicBlock::from(b));
    }
}

#[test]
fn sector_to_block() -> Result<(), MifareClassicError> {
    // 1k sectors
    assert_eq!(0u8, MifareClassicBlock::from(MifareClassicSector::try_from(0)?).into());
    assert_eq!(4u8, MifareClassicBlock::from(MifareClassicSector::try_from(1)?).into());
    assert_eq!(8u8, MifareClassicBlock::from(MifareClassicSector::try_from(2)?).into());
    assert_eq!(12u8, MifareClassicBlock::from(MifareClassicSector::try_from(3)?).into());
    assert_eq!(60u8, MifareClassicBlock::from(MifareClassicSector::try_from(15)?).into());

    // 4k sectors
    assert_eq!(124u8, MifareClassicBlock::from(MifareClassicSector::try_from(31)?).into());
    assert_eq!(128u8, MifareClassicBlock::from(MifareClassicSector::try_from(32)?).into());
    assert_eq!(144u8, MifareClassicBlock::from(MifareClassicSector::try_from(33)?).into());
    assert_eq!(160u8, MifareClassicBlock::from(MifareClassicSector::try_from(34)?).into());
    assert_eq!(240u8, MifareClassicBlock::from(MifareClassicSector::try_from(39)?).into());

    for b in 0..=39 {
        // Just making sure it doesnt panic.
        _ = MifareClassicBlock::from(MifareClassicSector::try_from(b)?);
    }

    Ok(())
}

#[test]
fn invalid_sector() {
    for i in 40..=255 {
        assert!(MifareClassicSector::try_from(i).is_err());
    }
}