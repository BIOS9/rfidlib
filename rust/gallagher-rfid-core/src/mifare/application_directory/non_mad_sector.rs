use crate::mifare::classic::Sector;

/// Mifare Application Directory (MAD) newtype validation wrapper for sectors that do not contain MAD data.
///
/// Based on:
/// - [NXP Application Note AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct NonMadSector(Sector);

impl NonMadSector {
    /// Iterate all non-MAD sectors in order:
    ///   1 to 15,
    ///   then 17 to 39.
    pub fn iter() -> impl Iterator<Item = NonMadSector> {
        Sector::iter().filter_map(|s| NonMadSector::try_from(s).ok())
    }
}

impl TryFrom<Sector> for NonMadSector {
    type Error = NonMadSectorError;

    /// Constructs a `NonMadSector`, validating the input against known constraints.
    ///
    /// Constraints (Error returned if not satisfied):
    /// 1. The sector cannot be 0, this sector is reserved for version 1 of the MIFARE Application Directory (MAD).
    /// 2. The sector cannot be 16, this sector is reserved for version 2 of the MIFARE Application Directory (MAD).
    fn try_from(sector: Sector) -> Result<Self, Self::Error> {
        match sector.into() {
            0 => Err(NonMadSectorError::ReservedForMadV1),
            16 => Err(NonMadSectorError::ReservedForMadV2),
            0..40 => Ok(NonMadSector(sector)),
            // Sector type cannot be greater than 39.
            _ => unreachable!("Sector had a value greater than 39 {}", sector),
        }
    }
}

impl From<NonMadSector> for Sector {
    fn from(value: NonMadSector) -> Self {
        value.0
    }
}

impl From<NonMadSector> for u8 {
    fn from(value: NonMadSector) -> Self {
        value.0.into()
    }
}

#[derive(Debug)]
pub enum NonMadSectorError {
    /// Sector is reserved for MADv1 data.
    ReservedForMadV1,
    /// Sector is reserved for MADv2 data.
    ReservedForMadV2,
}

#[cfg(test)]
mod tests {
    use crate::mifare::application_directory::non_mad_sector::NonMadSector;
    use crate::mifare::classic::{FourBlockSector, Sector};

    #[test]
    fn from_valid_sectors() {
        for sector in Sector::iter().filter(|&s| u8::from(s) != 0 && u8::from(s) != 16) {
            let nms = NonMadSector::try_from(sector).unwrap();
            assert_eq!(nms.0, sector);
        }
    }

    #[test]
    fn from_invalid_sectors() {
        let s0: Sector = FourBlockSector::S0.into();
        assert!(NonMadSector::try_from(s0).is_err());
        let s16: Sector = FourBlockSector::S16.into();
        assert!(NonMadSector::try_from(s16).is_err());
    }

    #[test]
    fn iterate() {
        let sectors = Sector::iter()
            .filter(|&s| u8::from(s) != 0 && u8::from(s) != 16)
            .map(|s| NonMadSector::try_from(s).unwrap());
        let non_mad_sectors = NonMadSector::iter();
        assert!(sectors.eq(non_mad_sectors));
    }

    #[test]
    fn to_sector() {
        let sectors = Sector::iter().filter(|&s| u8::from(s) != 0 && u8::from(s) != 16);
        let non_mad_sectors = NonMadSector::iter().map(Sector::from);
        assert!(sectors.eq(non_mad_sectors));
    }
    #[test]
    fn to_u8() {
        let sectors = Sector::iter()
            .filter(|&s| u8::from(s) != 0 && u8::from(s) != 16)
            .map(u8::from);
        let non_mad_sectors = NonMadSector::iter().map(u8::from);
        assert!(sectors.eq(non_mad_sectors));
    }
}
