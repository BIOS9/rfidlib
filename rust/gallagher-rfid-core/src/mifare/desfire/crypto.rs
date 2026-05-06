use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

/// Reader challenge used during AES authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RndA([u8; 16]);

impl RndA {
    /// Creates a reader challenge from caller-provided random bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw challenge bytes.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Challenge rotated one byte to the left.
    pub fn rotate_left(self) -> [u8; 16] {
        rotate_left(self.0)
    }
}

/// Card challenge returned during AES authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RndB([u8; 16]);

impl RndB {
    /// Creates a card challenge from decrypted bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw challenge bytes.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Challenge rotated one byte to the left.
    pub fn rotate_left(self) -> [u8; 16] {
        rotate_left(self.0)
    }
}

/// AES session key derived from `RndA` and `RndB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesSessionKey([u8; 16]);

impl AesSessionKey {
    /// Creates an AES session key from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Derives the `DESFire` AES session key from the reader and card challenges.
    pub fn derive(rnd_a: RndA, rnd_b: RndB) -> Self {
        let rnd_a = rnd_a.as_bytes();
        let rnd_b = rnd_b.as_bytes();
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&rnd_a[0..4]);
        out[4..8].copy_from_slice(&rnd_b[0..4]);
        out[8..12].copy_from_slice(&rnd_a[12..16]);
        out[12..16].copy_from_slice(&rnd_b[12..16]);
        Self(out)
    }

    /// Raw session-key bytes.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Full 16-byte AES-CMAC value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCmac([u8; 16]);

impl AesCmac {
    /// Calculates an AES-CMAC using the NIST SP 800-38B construction.
    pub fn calculate(key: &[u8; 16], data: &[u8]) -> Self {
        Self::calculate_chained(key, &[0u8; 16], data)
    }

    /// Calculates an AES-CMAC with caller-provided chaining state.
    ///
    /// Standard AES-CMAC uses an all-zero initial state. `DESFire` secure
    /// messaging also needs the previous full CMAC as chaining state.
    pub fn calculate_chained(key: &[u8; 16], initial_state: &[u8; 16], data: &[u8]) -> Self {
        let (subkey_1, subkey_2) = generate_cmac_subkeys(key);
        let (blocks, last_block_len) = split_cmac_blocks(data);
        let complete_last_block = last_block_len == 16;

        let mut state = *initial_state;
        let full_blocks_before_last = blocks.saturating_sub(1);
        for block_index in 0..full_blocks_before_last {
            let offset = block_index * 16;
            xor_block(
                &mut state,
                data[offset..offset + 16].try_into().expect("valid block"),
            );
            aes_encrypt_block(key, &mut state);
        }

        let mut last_block = [0u8; 16];
        if complete_last_block {
            let offset = full_blocks_before_last * 16;
            last_block.copy_from_slice(&data[offset..offset + 16]);
            xor_block(&mut last_block, &subkey_1);
        } else {
            let offset = full_blocks_before_last * 16;
            last_block[..last_block_len].copy_from_slice(&data[offset..]);
            last_block[last_block_len] = 0x80;
            xor_block(&mut last_block, &subkey_2);
        }

        xor_block(&mut state, &last_block);
        aes_encrypt_block(key, &mut state);
        Self(state)
    }

    /// Raw 16-byte CMAC value.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Returns the 8-byte `DESFire` MAC form.
    pub const fn desfire_mac(self) -> DesfireMac {
        DesfireMac::from_cmac(self)
    }
}

/// 8-byte `DESFire` MAC value derived from the full AES-CMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesfireMac([u8; 8]);

impl DesfireMac {
    /// Creates an 8-byte `DESFire` MAC from raw bytes.
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Creates the truncated `DESFire` MAC from a full CMAC.
    pub const fn from_cmac(cmac: AesCmac) -> Self {
        let bytes = cmac.as_bytes();
        Self([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Raw 8-byte MAC value.
    pub const fn as_bytes(self) -> [u8; 8] {
        self.0
    }
}

/// AES-CMAC chaining state used by `DESFire` secure messaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCmacChaining {
    state: [u8; 16],
}

impl AesCmacChaining {
    /// Creates zeroed CMAC chaining state for a fresh authenticated session.
    pub const fn new() -> Self {
        Self { state: [0u8; 16] }
    }

    /// Creates CMAC chaining state from a known full 16-byte value.
    pub const fn from_state(state: [u8; 16]) -> Self {
        Self { state }
    }

    /// Current full CMAC chaining state.
    pub const fn state(self) -> [u8; 16] {
        self.state
    }

    /// Resets the chaining state to zero.
    pub const fn reset(&mut self) {
        self.state = [0u8; 16];
    }

    /// Calculates a chained CMAC and stores the full result as the next state.
    pub fn update(&mut self, session_key: AesSessionKey, data: &[u8]) -> AesCmac {
        let cmac = AesCmac::calculate_chained(&session_key.as_bytes(), &self.state, data);
        self.state = cmac.as_bytes();
        cmac
    }
}

impl Default for AesCmacChaining {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates the CRC32 variant used inside encrypted `DESFire` EV1 responses.
pub fn desfire_crc32(data: &[u8]) -> [u8; 4] {
    let mut crc = 0xFFFF_FFFF;

    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 == 0 {
                crc >>= 1;
            } else {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            }
        }
    }

    crc.to_le_bytes()
}

/// Decrypts one AES-CBC block sequence in place.
pub fn aes_cbc_decrypt_in_place(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));

    let cipher = Aes128::new(key.into());
    let mut previous = *iv;

    for block in data.chunks_exact_mut(16) {
        let encrypted_block: [u8; 16] = block.try_into().expect("chunk size is exact");
        cipher.decrypt_block(block.into());
        xor_block(block, &previous);
        previous = encrypted_block;
    }
}

/// Encrypts one AES-CBC block sequence in place.
pub fn aes_cbc_encrypt_in_place(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));

    let cipher = Aes128::new(key.into());
    let mut previous = *iv;

    for block in data.chunks_exact_mut(16) {
        xor_block(block, &previous);
        cipher.encrypt_block(block.into());
        previous.copy_from_slice(block);
    }
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

fn rotate_left(mut bytes: [u8; 16]) -> [u8; 16] {
    bytes.rotate_left(1);
    bytes
}

fn split_cmac_blocks(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (1, 0);
    }

    let remainder = data.len() % 16;
    if remainder == 0 {
        (data.len() / 16, 16)
    } else {
        (data.len() / 16 + 1, remainder)
    }
}

fn xor_block(block: &mut [u8], mask: &[u8; 16]) {
    for (byte, mask) in block.iter_mut().zip(mask) {
        *byte ^= mask;
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::crypto::{
        aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, desfire_crc32, AesCmac,
        AesCmacChaining, AesSessionKey, RndA, RndB,
    };

    #[test]
    fn rotates_challenges_left() {
        let rnd_a = RndA::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);

        assert_eq!(
            rnd_a.rotate_left(),
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x00
            ]
        );
    }

    #[test]
    fn derives_aes_session_key() {
        let rnd_a = RndA::new([
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ]);
        let rnd_b = RndB::new([
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
            0xBE, 0xBF,
        ]);

        let session_key = AesSessionKey::derive(rnd_a, rnd_b);

        assert_eq!(
            session_key.as_bytes(),
            [
                0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3, 0xAC, 0xAD, 0xAE, 0xAF, 0xBC, 0xBD,
                0xBE, 0xBF,
            ]
        );
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        let mut data = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let original = data;

        aes_cbc_encrypt_in_place(&key, &iv, &mut data);
        assert_ne!(data, original);

        aes_cbc_decrypt_in_place(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn aes_cmac_matches_empty_nist_vector() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];

        let cmac = AesCmac::calculate(&key, &[]);

        assert_eq!(
            cmac.as_bytes(),
            [
                0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75,
                0x67, 0x46,
            ]
        );
    }

    #[test]
    fn aes_cmac_matches_complete_block_nist_vector() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let data = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];

        let cmac = AesCmac::calculate(&key, &data);

        assert_eq!(
            cmac.as_bytes(),
            [
                0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A,
                0x28, 0x7C,
            ]
        );
    }

    #[test]
    fn aes_cmac_matches_partial_block_nist_vector() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let data = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC,
            0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
        ];

        let cmac = AesCmac::calculate(&key, &data);

        assert_eq!(
            cmac.as_bytes(),
            [
                0xDF, 0xA6, 0x67, 0x47, 0xDE, 0x9A, 0xE6, 0x30, 0x30, 0xCA, 0x32, 0x61, 0x14, 0x97,
                0xC8, 0x27,
            ]
        );
    }

    #[test]
    fn desfire_mac_uses_first_eight_cmac_bytes() {
        let cmac = AesCmac::calculate(&[0x11; 16], &[0x22; 7]);

        assert_eq!(
            cmac.desfire_mac().as_bytes(),
            [
                cmac.as_bytes()[0],
                cmac.as_bytes()[1],
                cmac.as_bytes()[2],
                cmac.as_bytes()[3],
                cmac.as_bytes()[4],
                cmac.as_bytes()[5],
                cmac.as_bytes()[6],
                cmac.as_bytes()[7],
            ]
        );
    }

    #[test]
    fn desfire_crc32_matches_encrypted_read_trace() {
        let mut data = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x00,
        ];

        assert_eq!(desfire_crc32(&data), [0x82, 0xD5, 0x50, 0xCE]);

        data[16] = 0xAF;
        assert_ne!(desfire_crc32(&data), [0x82, 0xD5, 0x50, 0xCE]);
    }

    #[test]
    fn cmac_chaining_keeps_full_previous_cmac() {
        let rnd_a = RndA::new([
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ]);
        let rnd_b = RndB::new([
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
            0xBE, 0xBF,
        ]);
        let session_key = AesSessionKey::derive(rnd_a, rnd_b);
        let mut chaining = AesCmacChaining::new();

        let first = chaining.update(session_key, &[0xBD, 0x00, 0x00, 0x00]);
        let second = chaining.update(session_key, &[0xAF]);

        assert_eq!(chaining.state(), second.as_bytes());
        assert_eq!(
            second,
            AesCmac::calculate_chained(&session_key.as_bytes(), &first.as_bytes(), &[0xAF])
        );
    }
}
