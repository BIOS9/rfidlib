use crate::mifare::application_directory::MadVersion;
use crate::mifare::classic::Sector;

/// Mifare Application Directory (MAD) Card Publisher Sector (CPS) newtype validation wrapper.
///
/// Based on:
/// - [Proxmark3 MAD implementation](https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mad.c)
/// - [NXP Application Note AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CardPublisherSector(Sector);

impl CardPublisherSector {
    /// Constructs a `CardPublisherSector`, validating the input against known constraints.
    ///
    /// Constraints (Error returned if not satisfied):
    /// 1. The CPS cannot be 0, this sector is reserved for version 1 of the MIFARE Application Directory (MAD).
    /// 2. The CPS cannot be 16, this sector is reserved for version 2 of the MIFARE Application Directory (MAD).
    /// 3. The CPS cannot be greater than 39, because that's the highest sector in MIFARE Classic (0x27).
    /// 4. The CPS cannot be greater than 15 if the MAD version is 1.
    pub fn new(sector: Sector) -> Result<Self, CardPublisherSectorError> {
        match sector.into() {
            0 => Err(CardPublisherSectorError::ReservedForMadV1),
            16 => Err(CardPublisherSectorError::ReservedForMadV2),
            0..40 => Ok(CardPublisherSector(sector)),
            // Sector type cannot be greater than 39.
            _ => unreachable!("Sector had a value greater than 39 {}", sector),
        }
    }
}

impl From<CardPublisherSector> for Sector {
    fn from(value: CardPublisherSector) -> Self {
        value.0
    }
}

impl From<CardPublisherSector> for u8 {
    fn from(value: CardPublisherSector) -> Self {
        value.0.into()
    }
}

#[derive(Debug)]
pub enum CardPublisherSectorError {
    /// Sector is reserved for MADv1 data.
    ReservedForMadV1,
    /// Sector is reserved for MADv2 data.
    ReservedForMadV2,
}
