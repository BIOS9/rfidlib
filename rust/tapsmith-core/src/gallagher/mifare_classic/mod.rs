pub mod cad;

use heapless::Vec;

use crate::mifare::application_directory::{MadError, MifareApplicationDirectory, NonMadSector};
use crate::mifare::classic::{Block, FourBlockOffset, FourBlockSector, KeyProvider, Sector, Tag};

use super::credential::{CredentialError, GallagherCredential};
use cad::CardApplicationDirectory;

/// MAD AID for the Gallagher Card Application Directory.
pub const CAD_AID: u16 = 0x4811;
/// MAD AID for Gallagher credential sectors.
pub const CREDENTIAL_AID: u16 = 0x4812;

/// Key A for Gallagher credential sectors.
pub const CREDENTIAL_KEY_A: [u8; 6] = [0x16, 0x0A, 0x91, 0xD2, 0x9A, 0x9C];
/// Key B for Gallagher credential sectors.
pub const CREDENTIAL_KEY_B: [u8; 6] = [0xB7, 0xBF, 0x0C, 0x13, 0x06, 0x6E];
/// Access bits for credential sectors: Key A read, Key B read/write all blocks.
pub const CREDENTIAL_ACCESS_BITS: [u8; 3] = [0x78, 0x77, 0x88];

/// Default sector used by Gallagher for the MIFARE Classic CAD when no MAD is present.
pub const DEFAULT_CAD_SECTOR: FourBlockSector = FourBlockSector::S14;
/// Default sector used by Gallagher for a MIFARE Classic credential when no CAD is present.
pub const DEFAULT_CREDENTIAL_SECTOR: FourBlockSector = FourBlockSector::S15;

/// "www.cardax.com  " sentinel written to block 1 of every credential sector.
const CARDAX_SENTINEL: &[u8; 16] = b"www.cardax.com  ";

#[derive(Debug)]
pub enum Error {
    TagError(crate::mifare::classic::Error),
    MadError(MadError),
    /// CRC check failed for the CAD in the given sector.
    InvalidCadCrc(u8),
    /// Sector does not contain a valid Gallagher credential.
    InvalidCredential(u8),
    CredentialNotFound,
}

impl From<crate::mifare::classic::Error> for Error {
    fn from(e: crate::mifare::classic::Error) -> Self {
        Error::TagError(e)
    }
}

impl From<MadError> for Error {
    fn from(e: MadError) -> Self {
        Error::MadError(e)
    }
}

impl From<CredentialError> for Error {
    fn from(_: CredentialError) -> Self {
        // A decode error from a sector means that sector has an invalid credential.
        // Sector number is added by the caller.
        Error::InvalidCredential(0)
    }
}

/// All Gallagher credentials read from a MIFARE Classic tag, with their sector locations.
pub struct GallagherMifareClassic {
    pub credentials: Vec<(NonMadSector, GallagherCredential), 12>,
}

impl GallagherMifareClassic {
    /// Read all Gallagher credentials from a tag.
    ///
    /// Finds credential sectors via CAD if present, then MAD credential AIDs, then Gallagher's
    /// default credential sector. Sectors that fail to parse are silently skipped.
    pub fn read_from_tag<T: Tag>(
        tag: &mut T,
        key_provider: &impl KeyProvider,
    ) -> Result<Self, Error> {
        let mad = MifareApplicationDirectory::read_from_tag(tag, key_provider).ok();
        let mut credentials: Vec<(NonMadSector, GallagherCredential), 12> = Vec::new();

        if let Some(credential_sectors) =
            read_mad_cad_credential_sectors(tag, key_provider, mad.as_ref())
        {
            read_credential_sectors(tag, key_provider, &credential_sectors, &mut credentials);
            if !credentials.is_empty() {
                return Ok(Self { credentials });
            }
        }

        if let Ok(cad) =
            CardApplicationDirectory::read_from_tag(tag, DEFAULT_CAD_SECTOR, key_provider)
        {
            let credential_sectors: Vec<u8, 12> = cad.mappings.values().copied().collect();
            read_credential_sectors(tag, key_provider, &credential_sectors, &mut credentials);
            if !credentials.is_empty() {
                return Ok(Self { credentials });
            }
        }

        if let Some(mad) = &mad {
            let credential_sectors: Vec<u8, 38> = mad
                .iter_applications()
                .filter(|(_, aid)| aid.to_u16() == CREDENTIAL_AID)
                .map(|(sector, _)| u8::from(sector))
                .collect();
            read_credential_sectors(tag, key_provider, &credential_sectors, &mut credentials);
            if !credentials.is_empty() {
                return Ok(Self { credentials });
            }
        }

        let credential_sectors: Vec<u8, 1> =
            [DEFAULT_CREDENTIAL_SECTOR as u8].into_iter().collect();
        read_credential_sectors(tag, key_provider, &credential_sectors, &mut credentials);
        if credentials.is_empty() {
            return Err(Error::CredentialNotFound);
        }

        Ok(Self { credentials })
    }
}

fn read_mad_cad_credential_sectors<T: Tag>(
    tag: &mut T,
    key_provider: &impl KeyProvider,
    mad: Option<&MifareApplicationDirectory>,
) -> Option<Vec<u8, 12>> {
    let cad_sector = mad?
        .iter_applications()
        .find(|(_, aid)| aid.to_u16() == CAD_AID)
        .map(|(sector, _)| sector)?;

    let cad_four_block = match cad_sector.into() {
        Sector::FourBlock(s) => s,
        Sector::SixteenBlock(_) => return None,
    };

    let cad = CardApplicationDirectory::read_from_tag(tag, cad_four_block, key_provider).ok()?;
    Some(cad.mappings.values().copied().collect())
}

fn read_credential_sectors<T: Tag, const N: usize>(
    tag: &mut T,
    key_provider: &impl KeyProvider,
    credential_sectors: &Vec<u8, N>,
    credentials: &mut Vec<(NonMadSector, GallagherCredential), 12>,
) {
    for sector_num in credential_sectors {
        let Ok(sector) = Sector::try_from(*sector_num) else {
            continue;
        };
        let Ok(non_mad) = NonMadSector::try_from(sector) else {
            continue;
        };
        if credentials.iter().any(|(existing, _)| *existing == non_mad) {
            continue;
        }
        if let Ok(cred) = read_credential_sector(tag, sector, key_provider) {
            let _ = credentials.push((non_mad, cred));
        }
    }
}

/// Write a single Gallagher credential to a sector.
///
/// Writes the encoded credential + bitwise-inverse verification to block 0,
/// the Cardax sentinel to block 1, zeros to block 2, and the sector trailer
/// (with the provided keys) to block 3.
pub fn write_credential_to_sector<T: Tag>(
    tag: &mut T,
    sector: FourBlockSector,
    credential: &GallagherCredential,
    key_provider: &impl KeyProvider,
    key_a: &[u8; 6],
    key_b: &[u8; 6],
) -> Result<(), Error> {
    key_provider.authenticate(tag, sector.into())?;

    let encoded = credential.encode();

    // Block 0: 8-byte credential + 8-byte bitwise inverse.
    let mut block0 = [0u8; 16];
    block0[..8].copy_from_slice(&encoded);
    for i in 0..8 {
        block0[8 + i] = !encoded[i];
    }

    // Block 1: "www.cardax.com  "
    let block1 = *CARDAX_SENTINEL;

    // Block 2: zeros (MES placeholder).
    let block2 = [0u8; 16];

    // Block 3: sector trailer.
    let mut block3 = [0u8; 16];
    block3[..6].copy_from_slice(key_a);
    block3[6..9].copy_from_slice(&CREDENTIAL_ACCESS_BITS);
    block3[9] = 0xC1; // GPB: When no MES present
    block3[10..].copy_from_slice(key_b);

    tag.write_block(sector.block(FourBlockOffset::B0), block0)?;
    tag.write_block(sector.block(FourBlockOffset::B1), block1)?;
    tag.write_block(sector.block(FourBlockOffset::B2), block2)?;
    tag.write_block(sector.block(FourBlockOffset::B3), block3)?;

    Ok(())
}

fn read_credential_sector<T: Tag>(
    tag: &mut T,
    sector: Sector,
    key_provider: &impl KeyProvider,
) -> Result<GallagherCredential, Error> {
    key_provider.authenticate(tag, sector)?;

    let block0 = tag.read_block(Block::from(sector))?;

    // Last 8 bytes must be the bitwise inverse of the first 8.
    let valid = (0..8).all(|i| block0[i] == !block0[i + 8]);
    if !valid {
        return Err(Error::InvalidCredential(u8::from(Block::from(sector)) / 4));
    }

    let block1 = {
        let mut b = Block::from(sector);
        // Advance to the next block (block 1 of the sector).
        b = Block::from(u8::from(b) + 1);
        tag.read_block(b)?
    };

    if &block1 != CARDAX_SENTINEL {
        return Err(Error::InvalidCredential(u8::from(Block::from(sector)) / 4));
    }

    let credential_bytes: &[u8; 8] = block0[..8].try_into().unwrap();
    GallagherCredential::decode(credential_bytes)
        .map_err(|_| Error::InvalidCredential(u8::from(Block::from(sector)) / 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mifare::classic::{Error as ClassicError, KeyType};

    struct NoopKeyProvider;

    impl KeyProvider for NoopKeyProvider {
        fn authenticate<T: Tag>(&self, _tag: &mut T, _sector: Sector) -> Result<(), ClassicError> {
            Ok(())
        }
    }

    struct MockTag {
        blocks: [[u8; 16]; 64],
    }

    impl MockTag {
        const fn new() -> Self {
            Self {
                blocks: [[0u8; 16]; 64],
            }
        }

        fn write_cad_sector(&mut self, sector: FourBlockSector, cad: &CardApplicationDirectory) {
            let data = cad.to_bytes();
            self.blocks[usize::from(u8::from(sector.block(FourBlockOffset::B0)))]
                .copy_from_slice(&data[0..16]);
            self.blocks[usize::from(u8::from(sector.block(FourBlockOffset::B1)))]
                .copy_from_slice(&data[16..32]);
            self.blocks[usize::from(u8::from(sector.block(FourBlockOffset::B2)))]
                .copy_from_slice(&data[32..48]);
        }
    }

    impl Tag for MockTag {
        fn authenticate(
            &mut self,
            _sector: Sector,
            _key: &[u8; 6],
            _key_type: KeyType,
        ) -> Result<(), ClassicError> {
            Ok(())
        }

        fn read_block(&mut self, block: Block) -> Result<[u8; 16], ClassicError> {
            Ok(self.blocks[usize::from(u8::from(block))])
        }

        fn write_block(&mut self, block: Block, data: [u8; 16]) -> Result<(), ClassicError> {
            self.blocks[usize::from(u8::from(block))] = data;
            Ok(())
        }
    }

    #[test]
    fn reads_default_credential_sector_without_mad_or_cad() {
        let mut tag = MockTag::new();
        let credential = GallagherCredential::new(1, 123, 123_456, 1).unwrap();
        write_credential_to_sector(
            &mut tag,
            DEFAULT_CREDENTIAL_SECTOR,
            &credential,
            &NoopKeyProvider,
            &CREDENTIAL_KEY_A,
            &CREDENTIAL_KEY_B,
        )
        .unwrap();

        let result = GallagherMifareClassic::read_from_tag(&mut tag, &NoopKeyProvider).unwrap();

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(
            u8::from(result.credentials[0].0),
            DEFAULT_CREDENTIAL_SECTOR as u8
        );
        assert_eq!(result.credentials[0].1, credential);
    }

    #[test]
    fn reads_default_cad_sector_without_mad() {
        let mut tag = MockTag::new();
        let credential_sector = FourBlockSector::S13;
        let credential = GallagherCredential::new(2, 12_345, 6_789, 3).unwrap();
        write_credential_to_sector(
            &mut tag,
            credential_sector,
            &credential,
            &NoopKeyProvider,
            &CREDENTIAL_KEY_A,
            &CREDENTIAL_KEY_B,
        )
        .unwrap();
        let cad = CardApplicationDirectory::new([(
            (credential.region_code, credential.facility_code),
            credential_sector as u8,
        )]);
        tag.write_cad_sector(DEFAULT_CAD_SECTOR, &cad);

        let result = GallagherMifareClassic::read_from_tag(&mut tag, &NoopKeyProvider).unwrap();

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(u8::from(result.credentials[0].0), credential_sector as u8);
        assert_eq!(result.credentials[0].1, credential);
    }
}
