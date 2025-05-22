use crate::mifare::classic::{
    sector::{FourBlockSector, MifareClassicSectorIndex4},
    MifareClassic, MifareClassicError, MifareClassicKeyProvider, MifareClassicSector,
};

use super::{card_publisher_sector::CardPublisherSector, mad_application_id::MadAid};

pub enum MadVersion {
    V1,
    V2,
}

pub struct MifareApplicationDirectory {
    multi_application_card: bool,
    mad_version: MadVersion,
    card_publisher_sector: Option<CardPublisherSector>,
    applications: std::collections::BTreeMap<u8, MadAid>,
}

impl MifareApplicationDirectory {
    /// Default key A for Mifare Application Directory (MAD) sectors.
    pub const MAD_KEY_A: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    /// Default key B for Mifare Application Directory (MAD) sectors.
    pub const MAD_KEY_B: [u8; 6] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    /// Default access bits for Mifare Application Directory (MAD) sectors.
    pub const MAD_ACCESS_BITS: [u8; 3] = [0x78, 0x77, 0x88];

    // pub fn create(
    //     multi_application_card: bool,
    //     mad_version: MadVersion,
    //     card_publisher_sector: Option<CardPublisherSector>,
    //     applications: &std::collections::BTreeMap<u8, MadAid>,
    // ) -> Result<Self, MadError> {
    //     // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding
    //     // sector 0 since that means the value is absent).
    //     match mad_version {
    //         MadVersion::V1 => {
    //             if card_publisher_sector.into() >= 0x10 {
    //                 return Err(MadError::InvalidCardPublisherSectorForMadV1(
    //                     card_publisher_sector,
    //                 ));
    //             }
    //         }
    //         _ => {}
    //     }
    //     // e.g. check mad_version, card_publisher_sector validity, etc.

    //     // Build all applications with default FREE for missing entries...

    //     Ok(Self {
    //         multi_application_card,
    //         mad_version,
    //         card_publisher_sector,
    //         applications: applications.clone(),
    //     })
    // }

    pub fn read_from_tag<T: MifareClassic>(
        tag: &mut T,
        key_provider: &impl MifareClassicKeyProvider,
    ) -> Result<Self, MadError> {
        // Sector 0 must be present and readable MADv1
        let mad_v1_sector = FourBlockSector::S0;
        key_provider.authenticate(tag, mad_v1_sector)?;

        // let block3 = tag.read_block() // Block 3 contains the General Purpose Byte, Keys and access conditions.

        // Authenticate, read blocks, validate CRC, decode AIDs...
        todo!()
    }

    pub fn write_to_tag<T: MifareClassic>(
        &self,
        tag: &mut T,
        key_provider: &impl MifareClassicKeyProvider,
    ) -> Result<(), MadError> {
        // Write MAD to blocks
        todo!()
    }

    pub fn multi_application_card(&self) -> bool {
        self.multi_application_card
    }
}

pub enum MadError {
    InvalidCardPublisherSectorForMadV1(CardPublisherSector),
    CardError(MifareClassicError),
}

impl From<MifareClassicError> for MadError {
    fn from(error: MifareClassicError) -> Self {
        MadError::CardError(error)
    }
}
