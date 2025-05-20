use crate::mifare::classic::MifareClassicSector;

/// Mifare Application Directory (MAD) Card Publisher Sector (CPS) newtype validation wrapper.
///
/// Based on:
/// - [Proxmark3 MAD implementation](https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mad.c)
/// - [NXP Application Note AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CardPublisherSector(MifareClassicSector);

impl CardPublisherSector {
    /// Constructs a `CardPublisherSector`, validating the input against known constraints.
    /// 
    /// Returns an error if:
    /// 1. The CPS cannot be 0x00, this sector is reserved for version 1 of the Mifare Application Directory (MAD).
    /// 2. The CPS cannot be 0x10, this sector is reserved for version 2 of the Mifare Application Directory (MAD).
    /// 3. The CPS cannot be greater than 0x27, because the highest sector in Mifare Classic is 39 (0x27).
    pub fn new(sector: MifareClassicSector) -> Result<Self, CardPublisherSectorError> {
        match sector.into() {
            0x00 => Err(CardPublisherSectorError::ReservedForMadV1),
            0x10 => Err(CardPublisherSectorError::ReservedForMadV2),
            0x28..=u8::MAX => Err(CardPublisherSectorError::SectorOutOfRange(sector)),
            _ => Ok(CardPublisherSector(sector)),
        }
    }
}

impl From<CardPublisherSector> for MifareClassicSector {
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
    ReservedForMadV1,
    ReservedForMadV2,
    SectorOutOfRange(MifareClassicSector),
}
