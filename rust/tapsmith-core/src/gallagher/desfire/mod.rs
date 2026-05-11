//! Gallagher credential reading for MIFARE `DESFire` cards.
//!
//! Based on the public Gallagher `DESFire` format research and the Proxmark3
//! Gallagher implementation.

pub mod cad;
pub mod key;

use heapless::Vec;

use crate::{
    gallagher::credential::{CredentialError, GallagherCredential},
    mifare::desfire::{
        application::ApplicationId,
        crypto::RndA,
        error::Error as DesfireError,
        file::{CommunicationMode, FileId, FileSettingsDetails},
        framing::FrameCodec,
        key::KeyNumber,
        transport::Transport,
        types::U24,
        Desfire,
    },
};

pub use cad::GallagherDesfireCadEntry;
pub use key::{GallagherDesfireKeySource, GALLAGHER_DEFAULT_SITE_KEY};

/// Maximum number of Gallagher `DESFire` credential applications tracked.
pub const MAX_GALLAGHER_DESFIRE_CREDENTIALS: usize = 12;

/// First known Gallagher `DESFire` card-data application AID, raw `SelectApplication` byte order.
pub const GALLAGHER_DESFIRE_CARD_DATA_AID_START_BYTES: [u8; 3] = [0xF4, 0x81, 0x20];

/// Last known Gallagher `DESFire` card-data application AID, raw `SelectApplication` byte order.
pub const GALLAGHER_DESFIRE_CARD_DATA_AID_END_BYTES: [u8; 3] = [0xF4, 0x81, 0x2B];

const CARD_DATA_FILE_ID: u8 = 0x00;

/// A decoded Gallagher `DESFire` credential with source metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GallagherDesfireCredential {
    pub application_id: ApplicationId,
    pub file_id: FileId,
    pub credential: GallagherCredential,
    pub raw_credential: [u8; 8],
    pub cad_entry: Option<GallagherDesfireCadEntry>,
}

/// All Gallagher credentials read from a `DESFire` card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GallagherDesfire {
    pub credentials: Vec<GallagherDesfireCredential, MAX_GALLAGHER_DESFIRE_CREDENTIALS>,
}

/// Errors raised by Gallagher `DESFire` reading and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Desfire(DesfireError),
    Credential(CredentialError),
    InvalidCredentialLength,
    InvalidCredentialInverse,
    CredentialNotFound,
    InvalidUidLength(usize),
    InvalidKdfInput,
}

impl From<DesfireError> for Error {
    fn from(error: DesfireError) -> Self {
        Self::Desfire(error)
    }
}

impl From<CredentialError> for Error {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

/// Read-only Gallagher `DESFire` reader.
pub struct GallagherDesfireReader;

impl GallagherDesfireReader {
    /// Reads Gallagher `DESFire` credentials using a fixed reader challenge.
    ///
    /// Prefer [`Self::read_from_desfire_with_rnd_a`] when the caller can provide
    /// fresh random bytes for AES authentication.
    pub fn read_from_desfire<T, C>(
        desfire: &mut Desfire<T, C>,
        key_source: GallagherDesfireKeySource,
    ) -> Result<GallagherDesfire, Error>
    where
        T: Transport,
        C: FrameCodec,
    {
        Self::read_from_desfire_with_rnd_a(desfire, key_source, RndA::new([0u8; 16]))
    }

    /// Reads Gallagher `DESFire` credentials using caller-provided AES reader randomness.
    pub fn read_from_desfire_with_rnd_a<T, C>(
        desfire: &mut Desfire<T, C>,
        key_source: GallagherDesfireKeySource,
        rnd_a: RndA,
    ) -> Result<GallagherDesfire, Error>
    where
        T: Transport,
        C: FrameCodec,
    {
        desfire.select_application(ApplicationId::PICC)?;
        let uid = desfire.get_version()?.uid();

        let mut candidates: Vec<CandidateApplication, MAX_GALLAGHER_DESFIRE_CREDENTIALS> =
            Vec::new();
        if cad::read_candidates(desfire, &mut candidates).is_err() {
            push_card_data_range(&mut candidates);
        }
        if candidates.is_empty() {
            push_card_data_range(&mut candidates);
        }

        let mut credentials = Vec::new();
        for candidate in candidates {
            if let Ok(credential) =
                read_credential_application(desfire, key_source, uid, rnd_a, candidate)
            {
                let _ = credentials.push(credential);
            }
        }

        if credentials.is_empty() {
            return Err(Error::CredentialNotFound);
        }

        Ok(GallagherDesfire { credentials })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CandidateApplication {
    application_id: ApplicationId,
    cad_entry: Option<GallagherDesfireCadEntry>,
}

fn push_card_data_range(
    candidates: &mut Vec<CandidateApplication, MAX_GALLAGHER_DESFIRE_CREDENTIALS>,
) {
    for last_byte in GALLAGHER_DESFIRE_CARD_DATA_AID_START_BYTES[2]
        ..=GALLAGHER_DESFIRE_CARD_DATA_AID_END_BYTES[2]
    {
        let _ = candidates.push(CandidateApplication {
            application_id: ApplicationId::from_bytes([0xF4, 0x81, last_byte]),
            cad_entry: None,
        });
    }
}

fn read_credential_application<T, C>(
    desfire: &mut Desfire<T, C>,
    key_source: GallagherDesfireKeySource,
    uid: [u8; 7],
    rnd_a: RndA,
    candidate: CandidateApplication,
) -> Result<GallagherDesfireCredential, Error>
where
    T: Transport,
    C: FrameCodec,
{
    desfire.select_application(candidate.application_id)?;

    let key_number = KeyNumber::new(0).expect("key 0 is valid");
    let key = key::diversify_aes_key(
        key_source.site_key(),
        &uid,
        key_number.as_byte(),
        candidate.application_id,
    )?;
    desfire.authenticate_aes_with_rnd_a(key_number, &key, rnd_a)?;

    let file_id = FileId::new(CARD_DATA_FILE_ID).expect("file 0 is valid");
    let settings = desfire.get_file_settings(file_id)?;
    let length = match settings.details() {
        FileSettingsDetails::Data { size } => size,
        _ => U24::new(16).expect("16 is a valid U24"),
    };

    let mut data: Vec<u8, 64> = Vec::new();
    match settings.communication_mode() {
        CommunicationMode::Plain => desfire.read_data(
            file_id,
            U24::new(0).expect("zero is a valid U24"),
            length,
            &mut data,
        )?,
        CommunicationMode::Maced => desfire.read_data_maced(
            file_id,
            U24::new(0).expect("zero is a valid U24"),
            length,
            &mut data,
        )?,
        CommunicationMode::Enciphered => desfire.read_data_enciphered(
            file_id,
            U24::new(0).expect("zero is a valid U24"),
            length,
            &mut data,
        )?,
    }

    let (credential, raw_credential) = decode_credential_file(data.as_slice())?;
    Ok(GallagherDesfireCredential {
        application_id: candidate.application_id,
        file_id,
        credential,
        raw_credential,
        cad_entry: candidate.cad_entry,
    })
}

fn decode_credential_file(data: &[u8]) -> Result<(GallagherCredential, [u8; 8]), Error> {
    if data.len() < 16 {
        return Err(Error::InvalidCredentialLength);
    }

    let raw_credential: [u8; 8] = data[..8].try_into().expect("slice length is checked");
    let valid_inverse = raw_credential
        .iter()
        .zip(&data[8..16])
        .all(|(left, right)| *right == !*left);
    if !valid_inverse {
        return Err(Error::InvalidCredentialInverse);
    }

    Ok((
        GallagherCredential::decode(&raw_credential)?,
        raw_credential,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CREDENTIAL_FILE: [u8; 16] = [
        0xA3, 0xB4, 0xB0, 0xC1, 0x51, 0xB0, 0xA3, 0x34, 0x5C, 0x4B, 0x4F, 0x3E, 0xAE, 0x4F, 0x5C,
        0xCB,
    ];

    #[test]
    fn decodes_research_credential_file() {
        let (credential, raw) = decode_credential_file(&EXAMPLE_CREDENTIAL_FILE).unwrap();

        assert_eq!(
            credential,
            GallagherCredential::new(12, 0x1337, 0xF00D, 3).unwrap()
        );
        assert_eq!(raw, EXAMPLE_CREDENTIAL_FILE[..8]);
    }

    #[test]
    fn rejects_bad_inverse_half() {
        let mut file = EXAMPLE_CREDENTIAL_FILE;
        file[15] ^= 0x01;

        assert_eq!(
            decode_credential_file(&file),
            Err(Error::InvalidCredentialInverse)
        );
    }

    #[test]
    fn rejects_short_credential_file() {
        assert_eq!(
            decode_credential_file(&EXAMPLE_CREDENTIAL_FILE[..15]),
            Err(Error::InvalidCredentialLength)
        );
    }

    #[test]
    fn decodes_pm3_default_key_trace_credential_result() {
        let expected = GallagherCredential::new(0, 12_345, 6_789, 1).unwrap();
        let encoded = expected.encode();
        let mut file = [0u8; 16];
        file[..8].copy_from_slice(&encoded);
        for (index, byte) in encoded.iter().enumerate() {
            file[8 + index] = !byte;
        }

        let (decoded, raw) = decode_credential_file(&file).unwrap();

        assert_eq!(decoded, expected);
        assert_eq!(raw, encoded);
    }

    #[test]
    fn card_data_file_is_standard_data_when_settings_are_used() {
        let settings = crate::mifare::desfire::FileSettings::new(
            crate::mifare::desfire::FileType::StandardData,
            CommunicationMode::Enciphered,
            crate::mifare::desfire::AccessRights::from_bytes([0x00, 0x20]),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap(),
            },
        );

        assert_eq!(
            settings.file_type(),
            crate::mifare::desfire::FileType::StandardData
        );
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
    }
}
