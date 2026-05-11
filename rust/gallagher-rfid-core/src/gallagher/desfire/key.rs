use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use heapless::Vec;

use crate::mifare::desfire::application::ApplicationId;

use super::Error;

/// Public default MIFARE site key used by Proxmark3's Gallagher command.
pub const GALLAGHER_DEFAULT_SITE_KEY: [u8; 16] = [
    0x31, 0x12, 0xB7, 0x38, 0xD8, 0x86, 0x2C, 0xCD, 0x34, 0x30, 0x2E, 0xB2, 0x99, 0xAA, 0xB4, 0x56,
];

/// Source of the MIFARE site key used for Gallagher `DESFire` key diversification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GallagherDesfireKeySource {
    /// Use the public default Gallagher site key.
    DefaultSiteKey,
    /// Use a caller-supplied 16-byte MIFARE site key.
    SiteKey([u8; 16]),
}

impl GallagherDesfireKeySource {
    pub(crate) const fn site_key(self) -> [u8; 16] {
        match self {
            Self::DefaultSiteKey => GALLAGHER_DEFAULT_SITE_KEY,
            Self::SiteKey(key) => key,
        }
    }
}

pub(crate) fn diversify_aes_key(
    site_key: [u8; 16],
    uid: &[u8],
    key_number: u8,
    application_id: ApplicationId,
) -> Result<[u8; 16], Error> {
    let mut input: Vec<u8, 11> = Vec::new();
    build_kdf_input(uid, key_number, application_id, &mut input)?;
    Ok(gallagher_an10922_aes(&site_key, input.as_slice()))
}

fn build_kdf_input<const N: usize>(
    uid: &[u8],
    key_number: u8,
    application_id: ApplicationId,
    out: &mut Vec<u8, N>,
) -> Result<(), Error> {
    if uid.len() != 4 && uid.len() != 7 {
        return Err(Error::InvalidUidLength(uid.len()));
    }
    if key_number > 2 {
        return Err(Error::InvalidKdfInput);
    }

    let aid = application_id.as_bytes();
    let include_uid =
        (key_number != 1 && application_id != ApplicationId::PICC) || aid == [0xF4, 0x81, 0x1F];
    if include_uid {
        out.extend_from_slice(uid)
            .map_err(|_| Error::InvalidKdfInput)?;
    }
    out.push(key_number).map_err(|_| Error::InvalidKdfInput)?;
    out.extend_from_slice(&aid)
        .map_err(|_| Error::InvalidKdfInput)?;
    Ok(())
}

fn gallagher_an10922_aes(site_key: &[u8; 16], input: &[u8]) -> [u8; 16] {
    let mut prefixed: Vec<u8, 32> = Vec::new();
    prefixed.push(0x01).expect("capacity is sufficient");
    prefixed
        .extend_from_slice(input)
        .expect("capacity is sufficient");
    aes_cmac_min_len(site_key, prefixed.as_slice(), 32)
}

fn aes_cmac_min_len(key: &[u8; 16], data: &[u8], min_len: usize) -> [u8; 16] {
    let (subkey_1, subkey_2) = generate_cmac_subkeys(key);
    let mut buffer = [0u8; 48];
    buffer[..data.len()].copy_from_slice(data);

    let mut len = data.len();
    if len == 0 || !len.is_multiple_of(16) || len < min_len {
        buffer[len] = 0x80;
        len += 1;
        while !len.is_multiple_of(16) || len < min_len {
            len += 1;
        }
        let last_block: &mut [u8; 16] = (&mut buffer[len - 16..len])
            .try_into()
            .expect("slice length is checked");
        xor_block(last_block, &subkey_2);
    } else {
        let last_block: &mut [u8; 16] = (&mut buffer[len - 16..len])
            .try_into()
            .expect("slice length is checked");
        xor_block(last_block, &subkey_1);
    }

    let mut state = [0u8; 16];
    for block in buffer[..len].chunks_exact_mut(16) {
        let block: &mut [u8; 16] = block.try_into().expect("chunk length is exact");
        xor_block(block, &state);
        aes_encrypt_block(key, block);
        state.copy_from_slice(block);
    }
    state
}

fn aes_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(key.into());
    cipher.encrypt_block(block.into());
}

fn generate_cmac_subkeys(key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut subkey_1 = [0u8; 16];
    aes_encrypt_block(key, &mut subkey_1);
    double_cmac_subkey(&mut subkey_1);

    let mut subkey_2 = subkey_1;
    double_cmac_subkey(&mut subkey_2);

    (subkey_1, subkey_2)
}

fn double_cmac_subkey(block: &mut [u8; 16]) {
    let carry = block[0] & 0x80 != 0;
    shift_left_one_bit(block);
    if carry {
        block[15] ^= 0x87;
    }
}

fn shift_left_one_bit(block: &mut [u8; 16]) {
    let mut carry = 0;
    for byte in block.iter_mut().rev() {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
}

fn xor_block(left: &mut [u8; 16], right: &[u8; 16]) {
    for (left_byte, right_byte) in left.iter_mut().zip(right) {
        *left_byte ^= *right_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_input_includes_uid_for_key_zero_app_key() {
        let mut input: Vec<u8, 11> = Vec::new();

        build_kdf_input(
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            0,
            ApplicationId::from_bytes([0xF4, 0x81, 0x20]),
            &mut input,
        )
        .unwrap();

        assert_eq!(
            input.as_slice(),
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0xF4, 0x81, 0x20]
        );
    }

    #[test]
    fn kdf_input_omits_uid_for_key_one_app_key() {
        let mut input: Vec<u8, 11> = Vec::new();

        build_kdf_input(
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            1,
            ApplicationId::from_bytes([0xF4, 0x81, 0x20]),
            &mut input,
        )
        .unwrap();

        assert_eq!(input.as_slice(), &[0x01, 0xF4, 0x81, 0x20]);
    }

    #[test]
    fn kdf_input_omits_uid_for_picc_key() {
        let mut input: Vec<u8, 11> = Vec::new();

        build_kdf_input(
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            0,
            ApplicationId::PICC,
            &mut input,
        )
        .unwrap();

        assert_eq!(input.as_slice(), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn kdf_input_preserves_raw_aid_byte_order() {
        let mut input: Vec<u8, 11> = Vec::new();

        build_kdf_input(
            &[0x04, 0x11, 0x22, 0x33],
            0,
            ApplicationId::from_bytes([0xF4, 0x81, 0x2F]),
            &mut input,
        )
        .unwrap();

        assert_eq!(
            input.as_slice(),
            &[0x04, 0x11, 0x22, 0x33, 0x00, 0xF4, 0x81, 0x2F]
        );
    }

    #[test]
    fn kdf_matches_an10922_aes_public_vector() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let input = [
            0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20,
            0x41, 0x62, 0x75,
        ];

        assert_eq!(
            gallagher_an10922_aes(&key, &input),
            [
                0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3, 0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA,
                0x91, 0x75,
            ]
        );
    }

    #[test]
    fn diversifies_default_site_key_for_research_app() {
        let key = diversify_aes_key(
            GALLAGHER_DEFAULT_SITE_KEY,
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            0,
            ApplicationId::from_bytes([0xF4, 0x81, 0x20]),
        )
        .unwrap();

        assert_eq!(key.len(), 16);
        assert_ne!(key, GALLAGHER_DEFAULT_SITE_KEY);
    }

    #[test]
    fn diversifies_default_site_key_from_pm3_uid_trace() {
        let key = diversify_aes_key(
            GALLAGHER_DEFAULT_SITE_KEY,
            &[0x04, 0x4F, 0x5F, 0x3A, 0x0A, 0x65, 0x80],
            0,
            ApplicationId::from_bytes([0xF4, 0x81, 0x20]),
        )
        .unwrap();

        assert_eq!(
            key,
            [
                0x5A, 0x4A, 0x06, 0xF0, 0x7F, 0x47, 0x44, 0xC0, 0xA6, 0x75, 0x67, 0x57, 0x1C, 0x3B,
                0xDF, 0x56,
            ]
        );
    }
}
