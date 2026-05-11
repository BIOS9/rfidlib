use heapless::Vec;

use crate::mifare::desfire::{
    application::ApplicationId, file::FileId, framing::FrameCodec, transport::Transport,
    types::U24, Desfire,
};

use super::{CandidateApplication, Error, MAX_GALLAGHER_DESFIRE_CREDENTIALS};

/// Gallagher `DESFire` Card Application Directory AID, in raw `SelectApplication` byte order.
pub const GALLAGHER_DESFIRE_CAD_AID_BYTES: [u8; 3] = [0xF4, 0x81, 0x2F];

const MAX_CAD_BYTES: usize = 36 * 3;

/// One CAD entry that pointed to a Gallagher `DESFire` credential application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GallagherDesfireCadEntry {
    pub region_code: u8,
    pub facility_code: u16,
    pub application_id: ApplicationId,
}

pub(crate) fn read_candidates<T, C>(
    desfire: &mut Desfire<T, C>,
    candidates: &mut Vec<CandidateApplication, MAX_GALLAGHER_DESFIRE_CREDENTIALS>,
) -> Result<(), Error>
where
    T: Transport,
    C: FrameCodec,
{
    desfire.select_application(ApplicationId::from_bytes(GALLAGHER_DESFIRE_CAD_AID_BYTES))?;

    let mut cad_data: Vec<u8, MAX_CAD_BYTES> = Vec::new();
    for file_number in 0..=2 {
        let file_id = FileId::new(file_number)?;
        let mut file_data: Vec<u8, 36> = Vec::new();
        if desfire
            .read_data(
                file_id,
                U24::new(0).expect("zero is a valid U24"),
                U24::new(36).expect("36 is a valid U24"),
                &mut file_data,
            )
            .is_ok()
        {
            cad_data
                .extend_from_slice(file_data.as_slice())
                .map_err(|_| Error::InvalidCredentialLength)?;
        }
    }

    parse_entries(cad_data.as_slice(), candidates);
    if candidates.is_empty() {
        return Err(Error::CredentialNotFound);
    }
    Ok(())
}

fn parse_entries(
    data: &[u8],
    out: &mut Vec<CandidateApplication, MAX_GALLAGHER_DESFIRE_CREDENTIALS>,
) {
    for entry in data.chunks_exact(6) {
        if entry.iter().all(|byte| *byte == 0) {
            continue;
        }

        let application_id = ApplicationId::from_bytes([entry[5], entry[4], entry[3]]);
        let cad_entry = GallagherDesfireCadEntry {
            region_code: entry[0],
            facility_code: (u16::from(entry[1]) << 8) | u16::from(entry[2]),
            application_id,
        };
        let _ = out.push(CandidateApplication {
            application_id,
            cad_entry: Some(cad_entry),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_research_cad_entries_and_skips_zeroes() {
        let cad = [
            0x0C, 0x13, 0x37, 0x20, 0x81, 0xF4, 0x0D, 0x13, 0x38, 0x21, 0x81, 0xF4, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = Vec::new();

        parse_entries(&cad, &mut out);

        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].cad_entry.unwrap(),
            GallagherDesfireCadEntry {
                region_code: 12,
                facility_code: 0x1337,
                application_id: ApplicationId::from_bytes([0xF4, 0x81, 0x20])
            }
        );
        assert_eq!(out[1].application_id.as_bytes(), [0xF4, 0x81, 0x21]);
    }

    #[test]
    fn parses_pm3_default_key_trace_cad_entry() {
        let cad_file = [
            0x00, 0x30, 0x39, 0x20, 0x81, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = Vec::new();

        parse_entries(&cad_file, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].cad_entry.unwrap(),
            GallagherDesfireCadEntry {
                region_code: 0,
                facility_code: 12_345,
                application_id: ApplicationId::from_bytes([0xF4, 0x81, 0x20])
            }
        );
    }
}
