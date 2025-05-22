use core::{fmt, mem::transmute};

use super::{
    sector::{FourBlockSector, Sector, Sector::*, SixteenBlockSector},
    Error,
};

/// Represents offset of blocks in a four block MIFARE Classic sector.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum FourBlockOffset {
    B0 = 0,
    B1,
    B2,
    B3,
}

impl FourBlockOffset {
    /// Converts a u8 block index into a `FourBlockOffset` enum variant.
    ///
    /// # Panics
    /// This code will panic if `block` is greater than 3 because there are only four blocks in some MIFARE classic sectors.
    fn from_u8(block: u8) -> Self {
        assert!(block <= Self::B3 as u8);
        unsafe { transmute(block) }
    }
}

impl TryFrom<u8> for FourBlockOffset {
    type Error = Error;

    fn try_from(block: u8) -> Result<Self, Self::Error> {
        match block {
            // 0 to 3 (inclusive) are always valid block offsets for four block sectors.
            0..=3 => Ok(FourBlockOffset::from_u8(block)),
            _ => Err(Error::InvalidBlock(block)),
        }
    }
}

/// Represents offset of blocks in a sixteen block MIFARE Classic sector.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SixteenBlockOffset {
    B0 = 0,
    B1,
    B2,
    B3,
    B4,
    B5,
    B6,
    B7,
    B8,
    B9,
    B10,
    B11,
    B12,
    B13,
    B14,
    B15,
}

impl SixteenBlockOffset {
    /// Converts a u8 block index into a `SixteenBlockOffset` enum variant.
    ///
    /// # Panics
    /// This code will panic if `block` is greater than 15 because there are only sixteen blocks in some MIFARE classic sectors.
    fn from_u8(block: u8) -> Self {
        assert!(block <= Self::B15 as u8);
        unsafe { transmute(block) }
    }
}

impl TryFrom<u8> for SixteenBlockOffset {
    type Error = Error;

    fn try_from(block: u8) -> Result<Self, Self::Error> {
        match block {
            // 0 to 15 (inclusive) are always valid block offsets for sixteen block sectors.
            0..=15 => Ok(SixteenBlockOffset::from_u8(block)),
            _ => Err(Error::InvalidBlock(block)),
        }
    }
}

/// Represents a valid MIFARE Classic block from 0 to 255.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Block(u8);

impl Block {
    pub fn from_four_block_sector(sector: FourBlockSector, offset: FourBlockOffset) -> Block {
        let sector = sector as u8;
        let offset = offset as u8;
        Block((sector * 4) + offset)
    }
    pub fn from_sixteen_block_sector(
        sector: SixteenBlockSector,
        offset: SixteenBlockOffset,
    ) -> Block {
        let sector = sector as u8;
        let offset = offset as u8;
        Block(((sector - 32) * 16) + 128 + offset)
    }
}

/// Converts a `MifareClassicBlock` into a u8 block address.
impl From<Block> for u8 {
    fn from(value: Block) -> Self {
        value.0
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Block {}", self.0)
    }
}

/// Converts a `u8` into a `MifareClassicBlock`.
///
/// Note: All `u8` values are valid since there are 256 blocks starting from 0 in MIFARE Classic.
impl From<u8> for Block {
    fn from(value: u8) -> Self {
        Block(value)
    }
}

/// Converts a sector into its starting block address.
///
/// Sector-to-block mapping:
/// - Sectors 0–31 -> Blocks 0-124 (4 blocks per sector)
/// - Sectors 32–39 -> Blocks 128-240 (16 blocks per sector)
impl From<Sector> for Block {
    fn from(sector: Sector) -> Self {
        match sector {
            FourBlock(s) => Block::from_four_block_sector(s, FourBlockOffset::B0),
            SixteenBlock(s) => Block::from_sixteen_block_sector(s, SixteenBlockOffset::B0),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::format;

    #[test]
    fn block_from_u8() {
        for i in 0u8..=u8::MAX {
            assert_eq!(i, Block::from(i).0);
        }
    }

    #[test]
    fn block_to_u8() {
        for i in 0u8..=u8::MAX {
            assert_eq!(i, u8::from(Block::from(i)));
        }
    }

    #[test]
    fn block_format() {
        for i in 0u8..=u8::MAX {
            let b = Block::from(i);
            let s = format!("{}", b);
            assert_eq!(s, format!("Block {}", i));
        }
    }

    #[test]
    fn block_from_four_block_sector() {
        assert_eq!(
            Block(0),
            Block::from_four_block_sector(FourBlockSector::S0, FourBlockOffset::B0)
        );
        assert_eq!(
            Block(3),
            Block::from_four_block_sector(FourBlockSector::S0, FourBlockOffset::B3)
        );

        for i in 0u8..=31 {
            let s = FourBlockSector::try_from(i).unwrap();
            for j in 0u8..=4 {
                let o = unsafe { std::mem::transmute(j) };
                let b = Block::from_four_block_sector(s, o);
                assert_eq!(i * 4 + j, b.0);
            }
        }
    }

    #[test]
    fn block_from_sixteen_block_sector() {
        assert_eq!(
            Block(128),
            Block::from_sixteen_block_sector(SixteenBlockSector::S32, SixteenBlockOffset::B0)
        );
        assert_eq!(
            Block(143),
            Block::from_sixteen_block_sector(SixteenBlockSector::S32, SixteenBlockOffset::B15)
        );

        for i in 32u8..=39 {
            let s = SixteenBlockSector::try_from(i).unwrap();
            for j in 0u8..=15 {
                let o = unsafe { std::mem::transmute(j) };
                let b = Block::from_sixteen_block_sector(s, o);
                assert_eq!(((i - 32) * 16) + j + 128, b.0);
            }
        }
    }

    #[test]
    fn block_from_sector() {
        fn convert4(sector: FourBlockSector) -> Block {
            Block::from(Sector::from(sector))
        }

        fn convert16(sector: SixteenBlockSector) -> Block {
            Block::from(Sector::from(sector))
        }

        assert_eq!(Block(0), convert4(FourBlockSector::S0));
        assert_eq!(Block(128), convert16(SixteenBlockSector::S32));

        for i in 0u8..=31 {
            let s = unsafe { std::mem::transmute(i) };
            let b = convert4(s);
            assert_eq!(i * 4, b.0);
            assert_eq!(Block(i * 4), b);
        }

        for i in 32u8..=39 {
            let s = unsafe { std::mem::transmute(i) };
            let b = convert16(s);
            assert_eq!(((i - 32) * 16) + 128, b.0);
            assert_eq!(Block(((i - 32) * 16) + 128), b);
        }
    }

    #[test]
    fn four_block_offset_from_u8_raw() {
        for i in 0u8..=3u8 {
            let block = FourBlockOffset::from_u8(i);
            assert_eq!(i, block as u8);
        }
        for i in 4u8..=u8::MAX {
            let result = std::panic::catch_unwind(|| FourBlockOffset::from_u8(i));
            assert!(result.is_err());
        }
    }

    #[test]
    fn sixteen_block_offset_from_u8_raw() {
        for i in 0u8..=15u8 {
            let block = SixteenBlockOffset::from_u8(i);
            assert_eq!(i, block as u8);
        }
        for i in 16u8..=u8::MAX {
            let result = std::panic::catch_unwind(|| SixteenBlockOffset::from_u8(i));
            assert!(result.is_err());
        }
    }

    #[test]
    fn four_block_offset_try_from_u8() {
        for i in 0u8..=3u8 {
            let block = FourBlockOffset::try_from(i).unwrap();
            assert_eq!(i, block as u8);
        }
        for i in 4u8..=u8::MAX {
            let result = FourBlockOffset::try_from(i);
            assert!(result.is_err());
        }
    }

    #[test]
    fn sixteen_block_offset_try_from_u8() {
        for i in 0u8..=15u8 {
            let block = SixteenBlockOffset::try_from(i).unwrap();
            assert_eq!(i, block as u8);
        }
        for i in 16u8..=u8::MAX {
            let result = SixteenBlockOffset::try_from(i);
            assert!(result.is_err());
        }
    }
}
