use core::{fmt, mem::transmute};

use crate::mifare::classic::{Block, Error, FourBlockOffset, SixteenBlockOffset};

/// Represents a valid MIFARE Classic 4 block sector index from 0 to 31.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum FourBlockSector {
    S0 = 0,
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    S12,
    S13,
    S14,
    S15,
    S16,
    S17,
    S18,
    S19,
    S20,
    S21,
    S22,
    S23,
    S24,
    S25,
    S26,
    S27,
    S28,
    S29,
    S30,
    S31,
}

impl FourBlockSector {
    /// Gets the specified block offset from the current sector.
    pub fn block(&self, offset: FourBlockOffset) -> Block {
        Block::from_four_block_sector(*self, offset)
    }

    /// Converts a u8 sector index into a `FourBlockSector` enum variant.
    ///
    /// # Panics
    /// This code will panic if `sector` is greater than 31 because there are only 32 four block sectors in MIFARE classic.
    fn from_u8(sector: u8) -> Self {
        assert!(sector <= Self::S31 as u8);
        unsafe { transmute(sector) }
    }
}

/// Converts a `u8` into a valid `FourBlockSector`.
impl TryFrom<u8> for FourBlockSector {
    type Error = Error;

    fn try_from(sector: u8) -> Result<Self, Self::Error> {
        match sector {
            // 0 to 31 (inclusive) are always valid four block sectors.
            0..=31 => Ok(FourBlockSector::from_u8(sector)),
            _ => Err(Error::InvalidSector(sector)),
        }
    }
}

/// Represents a valid MIFARE Classic 16 block sector index from 32 to 39.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SixteenBlockSector {
    S32 = 32,
    S33,
    S34,
    S35,
    S36,
    S37,
    S38,
    S39,
}

impl SixteenBlockSector {
    /// Gets the specified block offset from the current sector.
    pub fn block(&self, offset: SixteenBlockOffset) -> Block {
        Block::from_sixteen_block_sector(*self, offset)
    }

    /// Converts a u8 sector index into a `FourBlockSector` enum variant.
    ///
    /// # Panics
    /// This code will panic if `sector` is less than 32 or greater than 39 because those are the only sixteen block sectors in MIFARE classic.
    fn from_u8(sector: u8) -> Self {
        assert!(sector >= Self::S32 as u8);
        assert!(sector <= Self::S39 as u8);
        unsafe { transmute(sector) }
    }
}

/// Converts a `u8` into a valid `SixteenBlockSector`.
impl TryFrom<u8> for SixteenBlockSector {
    type Error = Error;

    fn try_from(sector: u8) -> Result<Self, Self::Error> {
        match sector {
            // 32 to 39 (inclusive) are always valid sixteen block sectors.
            32..=39 => Ok(SixteenBlockSector::from_u8(sector)),
            _ => Err(Error::InvalidSector(sector)),
        }
    }
}

/// Represents a MIFARE Classic sector of either four or sixteen blocks.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Sector {
    FourBlock(FourBlockSector),       // 0..=31
    SixteenBlock(SixteenBlockSector), // 32..=39
}

impl fmt::Display for Sector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sector {}", u8::from(*self))
    }
}

impl From<FourBlockSector> for Sector {
    fn from(value: FourBlockSector) -> Self {
        Sector::FourBlock(value)
    }
}

impl From<SixteenBlockSector> for Sector {
    fn from(value: SixteenBlockSector) -> Self {
        Sector::SixteenBlock(value)
    }
}

/// Converts a `Sector` into a `u8` sector address.
impl From<Sector> for u8 {
    fn from(value: Sector) -> Self {
        match value {
            Sector::FourBlock(index) => index as u8,
            Sector::SixteenBlock(index) => index as u8,
        }
    }
}

/// Attempts conversion of a `u8` into a `Sector`.
///
/// Valid values for a sector are 0..=39
impl TryFrom<u8> for Sector {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=31 => Ok(FourBlockSector::try_from(value)?.into()),
            32..=40 => Ok(SixteenBlockSector::try_from(value)?.into()),
            _ => Err(Error::InvalidSector(value)),
        }
    }
}

/// Converts a block address into its corresponding sector.
///
/// Block-to-sector mapping:
/// - Blocks 0–127 -> Sectors 0–31 (4 blocks per sector)
/// - Blocks 128–255 -> Sectors 32–39 (16 blocks per sector)
impl From<Block> for Sector {
    fn from(value: Block) -> Self {
        let block = u8::from(value);
        // Unsafe saves matching every individual enum variant.
        match block {
            0..=127 => FourBlockSector::from_u8(block / 4).into(),
            128..=255 => SixteenBlockSector::from_u8(((block - 128) / 16) + 32).into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::format;

    #[test]
    fn four_block_sector_try_from_u8() {
        for i in u8::MIN..=31u8 {
            let s = FourBlockSector::try_from(i).unwrap();
            assert_eq!(i, s as u8);
        }

        for i in 32u8..=u8::MAX {
            assert!(FourBlockSector::try_from(i).is_err());
        }
    }

    #[test]
    fn sixteen_block_sector_try_from_u8() {
        for i in u8::MIN..=31u8 {
            assert!(SixteenBlockSector::try_from(i).is_err());
        }

        for i in 32u8..=39u8 {
            let s = SixteenBlockSector::try_from(i).unwrap();
            assert_eq!(i, s as u8);
        }

        for i in 40u8..=u8::MAX {
            assert!(SixteenBlockSector::try_from(i).is_err());
        }
    }

    #[test]
    fn four_block_sector_block() {
        for i in u8::MIN..=31u8 {
            let s = FourBlockSector::from_u8(i);
            for j in u8::MIN..3u8 {
                let offset = FourBlockOffset::try_from(j).unwrap();
                let block = s.block(offset);
                assert_eq!((i * 4) + j, u8::from(block));
            }
        }
    }

    #[test]
    fn sixteen_block_sector_block() {
        for i in 32u8..=39u8 {
            let s = SixteenBlockSector::from_u8(i);
            for j in u8::MIN..15u8 {
                let offset = SixteenBlockOffset::try_from(j).unwrap();
                let block: Block = s.block(offset);
                assert_eq!(((i - 32) * 16) + 128 + j, u8::from(block));
            }
        }
    }

    #[test]
    fn four_block_sector_from_u8() {
        for i in u8::MIN..=31u8 {
            let sector = FourBlockSector::from_u8(i);
            assert_eq!(i, sector as u8);
        }

        for i in 32u8..=u8::MAX {
            let result = std::panic::catch_unwind(|| FourBlockSector::from_u8(i));
            assert!(result.is_err());
        }
    }

    #[test]
    fn sixteen_block_sector_from_u8() {
        for i in u8::MIN..=31u8 {
            let result = std::panic::catch_unwind(|| SixteenBlockSector::from_u8(i));
            assert!(result.is_err());
        }

        for i in 32u8..=39u8 {
            let sector = SixteenBlockSector::from_u8(i);
            assert_eq!(i, sector as u8);
        }

        for i in 40u8..=u8::MAX {
            let result = std::panic::catch_unwind(|| SixteenBlockSector::from_u8(i));
            assert!(result.is_err());
        }
    }

    #[test]
    fn sector_display() {
        for i in u8::MIN..=u8::MAX {
            if let Ok(sector) = Sector::try_from(i) {
                let s = format!("{}", sector);
                assert_eq!(s, format!("Sector {}", i));
            }
        }
    }

    #[test]
    fn sector_from_four_block_sector() {
        for i in u8::MIN..=31u8 {
            let sector = Sector::from(FourBlockSector::from_u8(i));
            match sector {
                Sector::FourBlock(s) => {
                    assert_eq!(i, s as u8);
                }
                _ => panic!("Expected four block sector"),
            }
        }
    }

    #[test]
    fn sector_from_sixteen_block_sector() {
        for i in 32u8..=39u8 {
            let sector = Sector::from(SixteenBlockSector::from_u8(i));
            match sector {
                Sector::SixteenBlock(s) => {
                    assert_eq!(i, s as u8);
                }
                _ => panic!("Expected sixteen block sector"),
            }
        }
    }

    #[test]
    fn u8_from_sector() {
        for i in u8::MIN..=31u8 {
            let sector = Sector::from(FourBlockSector::from_u8(i));
            match sector {
                Sector::FourBlock(_) => {
                    assert_eq!(i, u8::from(sector));
                }
                _ => panic!("Expected four block sector"),
            }
        }
        for i in 32u8..=39u8 {
            let sector = Sector::from(SixteenBlockSector::from_u8(i));
            match sector {
                Sector::SixteenBlock(_) => {
                    assert_eq!(i, u8::from(sector));
                }
                _ => panic!("Expected sixteen block sector"),
            }
        }
    }

    #[test]
    fn sector_try_from_u8() {
        for i in u8::MIN..=31u8 {
            let sector = Sector::try_from(i).unwrap();
            match sector {
                Sector::FourBlock(_) => {
                    assert_eq!(i, u8::from(sector));
                }
                _ => panic!("Expected four block sector"),
            }
        }
        for i in 32u8..=39u8 {
            let sector = Sector::try_from(i).unwrap();
            match sector {
                Sector::SixteenBlock(_) => {
                    assert_eq!(i, u8::from(sector));
                }
                _ => panic!("Expected sixteen block sector"),
            }
        }
        for i in 40u8..=u8::MAX {
            assert!(Sector::try_from(i).is_err());
        }
    }

    #[test]
    fn sector_from_block() {
        for i in u8::MIN..=127u8 {
            let block = Block::from(i);
            let sector = Sector::from(block);
            match sector {
                Sector::FourBlock(s) => {
                    assert_eq!(u8::from(block) / 4, s as u8);
                }
                _ => panic!("Expected four block sector"),
            }
        }
        for i in 128u8..=u8::MAX {
            let block = Block::from(i);
            let sector = Sector::from(block);
            match sector {
                Sector::SixteenBlock(s) => {
                    assert_eq!(((u8::from(block) - 128) / 16) + 32, s as u8);
                }
                _ => panic!("Expected sixteen block sector"),
            }
        }
    }
}
