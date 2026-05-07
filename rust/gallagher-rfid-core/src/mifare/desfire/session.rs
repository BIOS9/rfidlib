use heapless::Vec;

use crate::mifare::desfire::{
    command::CommandCode,
    crypto::{
        aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, AesCmacChaining, AesSessionKey,
        DesSessionKey, DesfireMac, ThreeKey3DesSessionKey, TwoKey3DesSessionKey,
    },
    error::Error,
    key::KeyNumber,
    status::Status,
};

const MAX_CMAC_INPUT_SIZE: usize = 256;

/// Authentication state for a `DESFire` command stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Unauthenticated,
    Authenticated(AuthenticatedSession),
}

/// Authenticated-session metadata and secure-messaging state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedSession {
    key_number: KeyNumber,
    state: AlgoState,
}

/// Per-algorithm session state (key material and chaining IV, bundled together).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlgoState {
    Aes(AesState),
    Des(DesState),
    TwoKey3Des(TwoKey3DesState),
    ThreeKey3Des(ThreeKey3DesState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AesState {
    key: AesSessionKey,
    chaining: AesCmacChaining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DesState {
    key: DesSessionKey,
    chaining: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TwoKey3DesState {
    key: TwoKey3DesSessionKey,
    chaining: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThreeKey3DesState {
    key: ThreeKey3DesSessionKey,
    chaining: [u8; 8],
}

impl AuthenticatedSession {
    /// Creates session state for a successful AES authentication.
    pub const fn new_aes(key_number: KeyNumber, session_key: AesSessionKey) -> Self {
        Self {
            key_number,
            state: AlgoState::Aes(AesState {
                key: session_key,
                chaining: AesCmacChaining::new(),
            }),
        }
    }

    /// Creates session state for a successful DES authentication.
    pub const fn new_des(key_number: KeyNumber, session_key: DesSessionKey) -> Self {
        Self {
            key_number,
            state: AlgoState::Des(DesState {
                key: session_key,
                chaining: [0u8; 8],
            }),
        }
    }

    /// Creates session state for a successful two-key 3DES authentication.
    pub const fn new_2tdea(key_number: KeyNumber, session_key: TwoKey3DesSessionKey) -> Self {
        Self {
            key_number,
            state: AlgoState::TwoKey3Des(TwoKey3DesState {
                key: session_key,
                chaining: [0u8; 8],
            }),
        }
    }

    /// Creates session state for a successful three-key 3DES authentication.
    pub const fn new_3tdea(key_number: KeyNumber, session_key: ThreeKey3DesSessionKey) -> Self {
        Self {
            key_number,
            state: AlgoState::ThreeKey3Des(ThreeKey3DesState {
                key: session_key,
                chaining: [0u8; 8],
            }),
        }
    }

    /// Key number used for the current authentication.
    pub const fn key_number(self) -> KeyNumber {
        self.key_number
    }

    /// Session key negotiated by the current authentication.
    pub fn session_key(self) -> SessionKey {
        match self.state {
            AlgoState::Aes(s) => SessionKey::Aes(s.key),
            AlgoState::Des(s) => SessionKey::Des(s.key),
            AlgoState::TwoKey3Des(s) => SessionKey::TwoKey3Des(s.key),
            AlgoState::ThreeKey3Des(s) => SessionKey::ThreeKey3Des(s.key),
        }
    }

    /// Cipher block size in bytes for this session's algorithm.
    ///
    /// AES uses 16-byte blocks; all DES variants use 8-byte blocks.
    pub const fn block_size(&self) -> usize {
        match self.state {
            AlgoState::Aes(_) => 16,
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => 8,
        }
    }

    /// CRC size in bytes appended inside encrypted payloads.
    ///
    /// DES and two-key 3DES use a 2-byte CRC16; three-key 3DES and AES use a 4-byte CRC32.
    pub const fn crc_size(&self) -> usize {
        match self.state {
            AlgoState::Aes(_) | AlgoState::ThreeKey3Des(_) => 4,
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) => 2,
        }
    }

    /// Returns the AES-specific session key and CMAC chaining state, if this is an AES session.
    ///
    /// Returns `None` for all other algorithm families.
    pub fn aes_state(&self) -> Option<(AesSessionKey, AesCmacChaining)> {
        match self.state {
            AlgoState::Aes(s) => Some((s.key, s.chaining)),
            _ => None,
        }
    }

    /// Calculates and stores the next command CMAC for this session.
    pub fn update_command_cmac(
        &mut self,
        command_code: CommandCode,
        command_data: &[u8],
    ) -> Result<DesfireMac, Error> {
        let mut input: Vec<u8, MAX_CMAC_INPUT_SIZE> = Vec::new();
        input
            .push(command_code.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        input
            .extend_from_slice(command_data)
            .map_err(|_| Error::CommandTooLong)?;

        match &mut self.state {
            AlgoState::Aes(s) => {
                let key = s.key;
                Ok(s.chaining.update(key, input.as_slice()).desfire_mac())
            }
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => {
                Err(Error::UnsupportedAlgorithm)
            }
        }
    }

    /// Calculates and stores the next response CMAC for this session.
    pub fn update_response_cmac(
        &mut self,
        status: Status,
        response_data: &[u8],
    ) -> Result<DesfireMac, Error> {
        let mut input: Vec<u8, MAX_CMAC_INPUT_SIZE> = Vec::new();
        input
            .extend_from_slice(response_data)
            .map_err(|_| Error::ResponseTooLong)?;
        input
            .push(status.as_byte())
            .map_err(|_| Error::ResponseTooLong)?;

        match &mut self.state {
            AlgoState::Aes(s) => {
                let key = s.key;
                Ok(s.chaining.update(key, input.as_slice()).desfire_mac())
            }
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => {
                Err(Error::UnsupportedAlgorithm)
            }
        }
    }

    /// Decrypts a CBC-ciphered block sequence in place using the current chaining state as IV.
    ///
    /// The chaining state is updated to the last ciphertext block after decryption,
    /// matching the `DESFire` secure-messaging IV progression.
    /// `data` must be a non-empty multiple of [`Self::block_size()`] bytes.
    pub fn cbc_decrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), Error> {
        match &mut self.state {
            AlgoState::Aes(s) => {
                debug_assert!(
                    !data.is_empty() && data.len().is_multiple_of(16),
                    "AES CBC data must be a non-empty multiple of 16 bytes"
                );
                let iv = s.chaining.state();
                let last_block: [u8; 16] =
                    data[data.len() - 16..].try_into().expect("length checked");
                aes_cbc_decrypt_in_place(&s.key.as_bytes(), &iv, data);
                s.chaining = AesCmacChaining::from_state(last_block);
                Ok(())
            }
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => {
                Err(Error::UnsupportedAlgorithm)
            }
        }
    }

    /// Encrypts a block sequence in place using the current chaining state as IV.
    ///
    /// The chaining state is updated to the last ciphertext block after encryption.
    /// `data` must be a non-empty multiple of [`Self::block_size()`] bytes.
    pub fn cbc_encrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), Error> {
        match &mut self.state {
            AlgoState::Aes(s) => {
                debug_assert!(
                    !data.is_empty() && data.len().is_multiple_of(16),
                    "AES CBC data must be a non-empty multiple of 16 bytes"
                );
                let iv = s.chaining.state();
                aes_cbc_encrypt_in_place(&s.key.as_bytes(), &iv, data);
                let last_block: [u8; 16] =
                    data[data.len() - 16..].try_into().expect("length checked");
                s.chaining = AesCmacChaining::from_state(last_block);
                Ok(())
            }
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => {
                Err(Error::UnsupportedAlgorithm)
            }
        }
    }
}

/// Authenticated secure-messaging key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKey {
    Des(DesSessionKey),
    TwoKey3Des(TwoKey3DesSessionKey),
    ThreeKey3Des(ThreeKey3DesSessionKey),
    Aes(AesSessionKey),
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        command::CommandCode,
        crypto::{AesCmac, AesSessionKey},
        key::KeyNumber,
        session::AuthenticatedSession,
    };

    #[test]
    fn command_cmac_updates_session_chaining_state() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x47, 0xDB, 0x4F, 0x91, 0x13, 0x14, 0x15, 0x16, 0x6E, 0xC6,
            0x58, 0x25,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        let mac = session
            .update_command_cmac(
                CommandCode::READ_DATA,
                &[0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00],
            )
            .unwrap();
        let expected_full_cmac = AesCmac::calculate(
            &session_key.as_bytes(),
            &[0xBD, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00],
        );

        assert_eq!(mac, expected_full_cmac.desfire_mac());
        assert_eq!(
            session.aes_state().unwrap().1.state(),
            expected_full_cmac.as_bytes()
        );
    }

    #[test]
    fn cbc_encrypt_decrypt_roundtrip_aes() {
        let session_key = AesSessionKey::new([0x11; 16]);
        let mut enc_session =
            AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);
        let mut dec_session =
            AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        let original = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut data = original;

        enc_session.cbc_encrypt_in_place(&mut data).unwrap();
        assert_ne!(data, original);

        dec_session.cbc_decrypt_in_place(&mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn cbc_encrypt_updates_chaining_to_last_ciphertext_block() {
        use crate::mifare::desfire::crypto::aes_cbc_encrypt_in_place;

        let session_key = AesSessionKey::new([0x22; 16]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);
        let mut data = [0x33u8; 32];

        session.cbc_encrypt_in_place(&mut data).unwrap();

        let expected_last_block: [u8; 16] = data[16..].try_into().unwrap();
        assert_eq!(session.aes_state().unwrap().1.state(), expected_last_block);

        // Encrypt a second block; IV should be last ciphertext block from previous call.
        let mut second = [0x44u8; 16];
        let mut expected_second = [0x44u8; 16];
        aes_cbc_encrypt_in_place(
            &session_key.as_bytes(),
            &expected_last_block,
            &mut expected_second,
        );

        session.cbc_encrypt_in_place(&mut second).unwrap();
        assert_eq!(second, expected_second);
    }

    #[test]
    fn block_size_and_crc_size() {
        use crate::mifare::desfire::crypto::{
            DesSessionKey, ThreeKey3DesSessionKey, TwoKey3DesSessionKey,
        };

        let kn = KeyNumber::new(0).unwrap();
        let aes = AuthenticatedSession::new_aes(kn, AesSessionKey::new([0; 16]));
        assert_eq!(aes.block_size(), 16);
        assert_eq!(aes.crc_size(), 4);

        let des = AuthenticatedSession::new_des(kn, DesSessionKey::new([0; 8]));
        assert_eq!(des.block_size(), 8);
        assert_eq!(des.crc_size(), 2);

        let tdea2 = AuthenticatedSession::new_2tdea(kn, TwoKey3DesSessionKey::new([0; 16]));
        assert_eq!(tdea2.block_size(), 8);
        assert_eq!(tdea2.crc_size(), 2);

        let tdea3 = AuthenticatedSession::new_3tdea(kn, ThreeKey3DesSessionKey::new([0; 24]));
        assert_eq!(tdea3.block_size(), 8);
        assert_eq!(tdea3.crc_size(), 4);
    }
}
