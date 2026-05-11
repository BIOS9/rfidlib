use heapless::Vec;

use crate::mifare::desfire::{
    command::CommandCode,
    crypto::{
        aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, des_cbc_decrypt_in_place,
        des_cbc_encrypt_in_place, des_cbc_mac, tdes2_cbc_decrypt_in_place,
        tdes2_cbc_encrypt_in_place, tdes2_cbc_mac, tdes3_cbc_decrypt_in_place,
        tdes3_cbc_encrypt_in_place, tdes3_cbc_mac, AesCmacChaining, AesSessionKey, DesSessionKey,
        DesfireMac, ThreeKey3DesSessionKey, TwoKey3DesSessionKey,
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
    secure_messaging_key: TwoKey3DesSessionKey,
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
        Self::new_2tdea_with_secure_messaging_key(key_number, session_key, session_key)
    }

    /// Creates session state for a 2TDEA authentication whose secure messaging key differs.
    pub const fn new_2tdea_with_secure_messaging_key(
        key_number: KeyNumber,
        session_key: TwoKey3DesSessionKey,
        secure_messaging_key: TwoKey3DesSessionKey,
    ) -> Self {
        Self {
            key_number,
            state: AlgoState::TwoKey3Des(TwoKey3DesState {
                key: session_key,
                secure_messaging_key,
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

    /// CRC size in bytes appended inside legacy encrypted payloads.
    ///
    /// DES and two-key 3DES use a 2-byte CRC16; three-key 3DES and AES use a 4-byte CRC32.
    pub const fn crc_size(&self) -> usize {
        match self.state {
            AlgoState::Aes(_) | AlgoState::ThreeKey3Des(_) => 4,
            AlgoState::Des(_) | AlgoState::TwoKey3Des(_) => 2,
        }
    }

    /// CRC size in bytes used by encrypted command plaintexts.
    ///
    /// EV1 secure messaging uses a CRC32 trailer for 2TDEA encrypted commands.
    pub const fn encrypted_command_crc_size(&self) -> usize {
        match self.state {
            AlgoState::Aes(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => 4,
            AlgoState::Des(_) => 2,
        }
    }

    /// CRC size in bytes used by encrypted `ReadData` response plaintexts.
    ///
    /// EV1 secure messaging returns a CRC32 trailer for 2TDEA encrypted reads,
    /// even though other 2TDEA encrypted payloads use CRC16.
    pub const fn encrypted_read_crc_size(&self) -> usize {
        match self.state {
            AlgoState::Aes(_) | AlgoState::TwoKey3Des(_) | AlgoState::ThreeKey3Des(_) => 4,
            AlgoState::Des(_) => 2,
        }
    }

    /// MAC size in bytes used on the wire for this session.
    ///
    /// All algorithms use 8 bytes: AES uses the first 8 of the 16-byte CMAC;
    /// DES variants use the full 8-byte CBC-MAC output.
    pub const fn mac_len(&self) -> usize {
        8
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
            AlgoState::Des(s) => {
                let mac = des_cbc_mac(&s.key.as_bytes(), &s.chaining, input.as_slice());
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
            }
            AlgoState::TwoKey3Des(s) => {
                let mac = tdes2_cbc_mac(
                    &s.secure_messaging_key.as_bytes(),
                    &s.chaining,
                    input.as_slice(),
                );
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
            }
            AlgoState::ThreeKey3Des(s) => {
                let mac = tdes3_cbc_mac(&s.key.as_bytes(), &s.chaining, input.as_slice());
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
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
            AlgoState::Des(s) => {
                let mac = des_cbc_mac(&s.key.as_bytes(), &s.chaining, input.as_slice());
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
            }
            AlgoState::TwoKey3Des(s) => {
                let mac = tdes2_cbc_mac(
                    &s.secure_messaging_key.as_bytes(),
                    &s.chaining,
                    input.as_slice(),
                );
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
            }
            AlgoState::ThreeKey3Des(s) => {
                let mac = tdes3_cbc_mac(&s.key.as_bytes(), &s.chaining, input.as_slice());
                s.chaining = mac;
                Ok(des_mac_to_desfire_mac(mac))
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
            AlgoState::Des(s) => {
                let last_block: [u8; 8] =
                    data[data.len() - 8..].try_into().expect("length checked");
                des_cbc_decrypt_in_place(&s.key.as_bytes(), &s.chaining, data);
                s.chaining = last_block;
                Ok(())
            }
            AlgoState::TwoKey3Des(s) => {
                let last_block: [u8; 8] =
                    data[data.len() - 8..].try_into().expect("length checked");
                tdes2_cbc_decrypt_in_place(&s.secure_messaging_key.as_bytes(), &s.chaining, data);
                s.chaining = last_block;
                Ok(())
            }
            AlgoState::ThreeKey3Des(s) => {
                let last_block: [u8; 8] =
                    data[data.len() - 8..].try_into().expect("length checked");
                tdes3_cbc_decrypt_in_place(&s.key.as_bytes(), &s.chaining, data);
                s.chaining = last_block;
                Ok(())
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
            AlgoState::Des(s) => {
                des_cbc_encrypt_in_place(&s.key.as_bytes(), &s.chaining, data);
                s.chaining = data[data.len() - 8..].try_into().expect("length checked");
                Ok(())
            }
            AlgoState::TwoKey3Des(s) => {
                tdes2_cbc_encrypt_in_place(&s.secure_messaging_key.as_bytes(), &s.chaining, data);
                s.chaining = data[data.len() - 8..].try_into().expect("length checked");
                Ok(())
            }
            AlgoState::ThreeKey3Des(s) => {
                tdes3_cbc_encrypt_in_place(&s.key.as_bytes(), &s.chaining, data);
                s.chaining = data[data.len() - 8..].try_into().expect("length checked");
                Ok(())
            }
        }
    }
}

fn des_mac_to_desfire_mac(mac: [u8; 8]) -> DesfireMac {
    DesfireMac::new(mac)
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
        crypto::{
            desfire_crc32, AesCmac, AesSessionKey, ThreeKey3DesSessionKey, TwoKey3DesSessionKey,
        },
        key::KeyNumber,
        session::AuthenticatedSession,
        status::Status,
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
        assert_eq!(aes.encrypted_command_crc_size(), 4);
        assert_eq!(aes.encrypted_read_crc_size(), 4);

        let des = AuthenticatedSession::new_des(kn, DesSessionKey::new([0; 8]));
        assert_eq!(des.block_size(), 8);
        assert_eq!(des.crc_size(), 2);
        assert_eq!(des.encrypted_command_crc_size(), 2);
        assert_eq!(des.encrypted_read_crc_size(), 2);

        let tdea2 = AuthenticatedSession::new_2tdea(kn, TwoKey3DesSessionKey::new([0; 16]));
        assert_eq!(tdea2.block_size(), 8);
        assert_eq!(tdea2.crc_size(), 2);
        assert_eq!(tdea2.encrypted_command_crc_size(), 4);
        assert_eq!(tdea2.encrypted_read_crc_size(), 4);

        let tdea3 = AuthenticatedSession::new_3tdea(kn, ThreeKey3DesSessionKey::new([0; 24]));
        assert_eq!(tdea3.block_size(), 8);
        assert_eq!(tdea3.crc_size(), 4);
        assert_eq!(tdea3.encrypted_command_crc_size(), 4);
        assert_eq!(tdea3.encrypted_read_crc_size(), 4);
    }

    // Proxmark trace: `hf mfdes formatpicc -n 0 -t aes`
    // Session key: 01 02 03 04 80 08 F7 4F 13 14 15 16 3E 9A 3B 1C
    // Command: 90 FC 00 00 00  (no payload)
    // Response: 1A 27 DE C4 EF 81 40 D4 91 00  (8-byte MAC + status OK)
    #[test]
    fn format_picc_cmac_matches_proxmark_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x80, 0x08, 0xF7, 0x4F, 0x13, 0x14, 0x15, 0x16, 0x3E, 0x9A,
            0x3B, 0x1C,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(CommandCode::FORMAT_PICC, &[])
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x1A, 0x27, 0xDE, 0xC4, 0xEF, 0x81, 0x40, 0xD4]
        );
    }

    // Proxmark trace: `hf mfdes deletefile --aid 111111 --fid 01 --keyno 0 --algo aes`
    // Session key: 01 02 03 04 90 1E 6D BC 13 14 15 16 69 C2 AA FA
    // Command: 90 DF 00 00 01 01 00  (fid=0x01)
    // Response: 36 2D 0D 63 08 43 E6 F9 91 00  (8-byte MAC + status OK)
    #[test]
    fn delete_file_cmac_matches_proxmark_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x90, 0x1E, 0x6D, 0xBC, 0x13, 0x14, 0x15, 0x16, 0x69, 0xC2,
            0xAA, 0xFA,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(CommandCode::DELETE_FILE, &[0x01])
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x36, 0x2D, 0x0D, 0x63, 0x08, 0x43, 0xE6, 0xF9]
        );
    }

    // Proxmark trace: `hf mfdes deleteapp --aid 222222 --algo aes --keyno 0`
    // PICC master key: 00..00 (default AES)
    // Session key reported by proxmark: 01 02 03 04 A3 63 2A 85 13 14 15 16 CA B9 DB E9
    // Command: 90 DA 00 00 03 22 22 22 00
    // Response: 01 C5 F1 0B 07 D4 C7 25 91 00  (8-byte MAC + status OK)
    #[test]
    fn delete_application_cmac_matches_picc_auth_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xA3, 0x63, 0x2A, 0x85, 0x13, 0x14, 0x15, 0x16, 0xCA, 0xB9,
            0xDB, 0xE9,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(CommandCode::DELETE_APPLICATION, &[0x22, 0x22, 0x22])
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x01, 0xC5, 0xF1, 0x0B, 0x07, 0xD4, 0xC7, 0x25]
        );
    }

    // Proxmark trace: `hf mfdes createfile --aid 222222 --fid 01 --amode encrypt --rrights key0
    //   --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes`
    // Session key: 01 02 03 04 24 36 0B AA 13 14 15 16 19 61 D1 BC
    // Command: 90 CD 00 00 07 01 03 00 00 10 00 00 00
    //   fid=0x01, comm_mode=0x03(enc), access=0x0000(all key0), size=0x000010
    // Response: CB C4 40 7F 5E 89 71 94 91 00  (8-byte MAC + status OK)
    #[test]
    fn create_std_data_file_cmac_matches_proxmark_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x24, 0x36, 0x0B, 0xAA, 0x13, 0x14, 0x15, 0x16, 0x19, 0x61,
            0xD1, 0xBC,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(
                CommandCode::CREATE_STD_DATA_FILE,
                &[0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00],
            )
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0xCB, 0xC4, 0x40, 0x7F, 0x5E, 0x89, 0x71, 0x94]
        );
    }

    // Proxmark trace: `hf mfdes changekey --aid 111111 --keyno 0 --algo aes
    //   --newkey 01020304050607080102030405060708 --newkeyno 0 --newalgo aes --verbose --apdu`
    // Session key: 01 02 03 04 03 95 69 17 13 14 15 16 06 EF 0E 66
    // No prior commands in session (chaining IV = all zeros at start of ChangeKey).
    // Command: 90 C4 00 00 21 00 30 3A D0 44 37 12 04 17 A1 73 00 80 96 D8 93 57 D9 92
    //                         36 A2 55 22 BF A7 7F F2 ED C2 51 66 66 EA 00
    //   key_no=0x00, encrypted=30 3A D0 44 37 12 04 17 A1 73 00 80 96 D8 93 57
    //                          D9 92 36 A2 55 22 BF A7 7F F2 ED C2 51 66 66 EA  (32 bytes)
    // Response: 91 00  (status OK only — session invalidated, no MAC)
    // Proxmark trace: `hf mfdes changekey --aid 111111 --keyno 0 --algo aes
    //   -k 01020304050607080102030405060708 --newkey 01020304050607080102030405060708
    //   --newkeyno 1 --newalgo aes --newver 01 --verbose --apdu`
    // Auth key 0 = 01..08 01..08; changing key 1 (old=all zeros, new=01..08 01..08, version=0x01)
    // Session key: 01 02 03 04 82 33 20 14 13 14 15 16 DA 96 DD 27
    // Command: 90 C4 00 00 21 01 FC 62 97 E0 29 ED 81 BA CD 1A 51 A2 6B 14 0E 37 26 5B 6D
    //                         0A 58 F0 FD 45 9A 13 CE 06 ED B8 F9 AC 00
    //   key_no=0x01, encrypted=FC..AC (32 bytes)
    // Response: C2 BA 20 0C 58 27 F6 93 91 00  (8-byte MAC + status OK)
    // Plaintext (decrypted): [key_xor(16) || version(0x01) || CRC32_a(4) || CRC32_b(4) || zeros(7)]
    //   CRC32_a: CRC32(cmd || key_no || key_xor || version) = 2F C6 C0 9C
    //   CRC32_b: CRC32(new_key) = 79 88 88 DA
    #[test]
    fn change_key_different_key_crypto_chain() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x82, 0x33, 0x20, 0x14, 0x13, 0x14, 0x15, 0x16, 0xDA, 0x96,
            0xDD, 0x27,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        let new_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        let old_key = [0u8; 16];
        let key_xor: [u8; 16] = core::array::from_fn(|i| new_key[i] ^ old_key[i]);
        let key_version: u8 = 0x01;

        let crc_a = desfire_crc32(&{
            let mut v = [0u8; 19];
            v[0] = CommandCode::CHANGE_KEY.as_byte();
            v[1] = 0x01; // key_no
            v[2..18].copy_from_slice(&key_xor);
            v[18] = key_version;
            v
        });
        let crc_b = desfire_crc32(&new_key);

        let mut plaintext = [0u8; 32];
        plaintext[..16].copy_from_slice(&key_xor);
        plaintext[16] = key_version;
        plaintext[17..21].copy_from_slice(&crc_a);
        plaintext[21..25].copy_from_slice(&crc_b);
        // bytes 25..32 zero-padded

        session.cbc_encrypt_in_place(&mut plaintext).unwrap();
        assert_eq!(
            plaintext,
            [
                0xFC, 0x62, 0x97, 0xE0, 0x29, 0xED, 0x81, 0xBA, 0xCD, 0x1A, 0x51, 0xA2, 0x6B, 0x14,
                0x0E, 0x37, 0x26, 0x5B, 0x6D, 0x0A, 0x58, 0xF0, 0xFD, 0x45, 0x9A, 0x13, 0xCE, 0x06,
                0xED, 0xB8, 0xF9, 0xAC
            ]
        );

        // After encryption chaining = last ciphertext block; response MAC verifies chain.
        let mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();
        assert_eq!(
            mac.as_bytes(),
            [0xC2, 0xBA, 0x20, 0x0C, 0x58, 0x27, 0xF6, 0x93]
        );
    }

    // Proxmark trace: `hf mfdes changekey --keyno 0 --algo aes
    //   --newkey 01020304050607080102030405060708 --newkeyno 0 --newalgo aes --newver 02`
    // PICC level (AID 000000). KeyNo byte = 0x80 (AES flag).
    // Session key: 01 02 03 04 0B 5D FE 1D 13 14 15 16 4C 6B C1 B3
    // Command data: 80 51 7B 64 96 3A CB 65 FB A3 FA 63 87 43 CE 9C F2 3F F7 F4
    //               99 7C 0B 70 14 1D 00 CF 07 09 E2 5E 29
    #[test]
    fn change_picc_key_crypto() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x0B, 0x5D, 0xFE, 0x1D, 0x13, 0x14, 0x15, 0x16, 0x4C, 0x6B,
            0xC1, 0xB3,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);
        let new_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        let key_version: u8 = 0x02;
        let key_no_byte: u8 = 0x80;
        let crc = desfire_crc32(&{
            let mut v = [0u8; 19];
            v[0] = CommandCode::CHANGE_KEY.as_byte();
            v[1] = key_no_byte;
            v[2..18].copy_from_slice(&new_key);
            v[18] = key_version;
            v
        });
        let mut plaintext = [0u8; 32];
        plaintext[..16].copy_from_slice(&new_key);
        plaintext[16] = key_version;
        plaintext[17..21].copy_from_slice(&crc);
        session.cbc_encrypt_in_place(&mut plaintext).unwrap();
        assert_eq!(
            plaintext,
            [
                0x51, 0x7B, 0x64, 0x96, 0x3A, 0xCB, 0x65, 0xFB, 0xA3, 0xFA, 0x63, 0x87, 0x43, 0xCE,
                0x9C, 0xF2, 0x3F, 0xF7, 0xF4, 0x99, 0x7C, 0x0B, 0x70, 0x14, 0x1D, 0x00, 0xCF, 0x07,
                0x09, 0xE2, 0x5E, 0x29
            ]
        );
        // No response MAC — card invalidates session on PICC key change.
    }

    #[test]
    fn change_key_same_key_crypto() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x03, 0x95, 0x69, 0x17, 0x13, 0x14, 0x15, 0x16, 0x06, 0xEF,
            0x0E, 0x66,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        let new_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];

        // CRC32 over [cmd=0xC4, key_no=0x00, new_key[0..16], key_version=0x02]
        let crc = desfire_crc32(&{
            let mut v = [0u8; 19];
            v[0] = CommandCode::CHANGE_KEY.as_byte();
            v[1] = 0x00;
            v[2..18].copy_from_slice(&new_key);
            v[18] = 0x02; // key version
            v
        });

        // Plaintext: [new_key(16) || key_version(1=0x02) || CRC32(4) || zeros(11)]
        let mut plaintext = [0u8; 32];
        plaintext[..16].copy_from_slice(&new_key);
        plaintext[16] = 0x02; // key version from --newver 02
        plaintext[17..21].copy_from_slice(&crc);
        // bytes 21..32 zero-padded

        session.cbc_encrypt_in_place(&mut plaintext).unwrap();
        assert_eq!(
            plaintext,
            [
                0x30, 0x3A, 0xD0, 0x44, 0x37, 0x12, 0x04, 0x17, 0xA1, 0x73, 0x00, 0x80, 0x96, 0xD8,
                0x93, 0x57, 0xD9, 0x92, 0x36, 0xA2, 0x55, 0x22, 0xBF, 0xA7, 0x7F, 0xF2, 0xED, 0xC2,
                0x51, 0x66, 0x66, 0xEA
            ]
        );
        // No response MAC — card invalidates session on same-key change.
    }

    // Proxmark trace: `hf mfdes chfilesettings --aid 111111 --fid 00 --amode encrypt
    //   --rrights free --wrights free --rwrights free --chrights key0 --algo aes --keyno 0`
    // Session key: 01 02 03 04 D4 E8 23 47 13 14 15 16 B1 EF FA FC
    // Step 1: GetFileSettings fid=0x00
    //   Command:  90 F5 00 00 01 00 00
    //   Response: 00 00 00 E0 20 00 00 D9 A3 18 EF 7D 09 F9 24 91 00
    // Step 2: ChangeFileSettings fid=0x00, new settings 03 E0 EE (encrypt, all free except change=key0)
    //   Command:  90 5F 00 00 11 00 8E 8C 90 DA 0C 1B 1A 9B 74 90 94 EC E7 96 2B 39 00
    //   Response: 93 91 BB 51 2D 1D 62 C1 91 00
    #[test]
    fn change_file_settings_crypto_chain() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xD4, 0xE8, 0x23, 0x47, 0x13, 0x14, 0x15, 0x16, 0xB1, 0xEF,
            0xFA, 0xFC,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        // Step 1: GetFileSettings fid=0x00
        session
            .update_command_cmac(CommandCode::GET_FILE_SETTINGS, &[0x00])
            .unwrap();
        let mac1 = session
            .update_response_cmac(
                Status::OperationOk,
                &[0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00],
            )
            .unwrap();
        assert_eq!(
            mac1.as_bytes(),
            [0xD9, 0xA3, 0x18, 0xEF, 0x7D, 0x09, 0xF9, 0x24]
        );

        // Step 2: ChangeFileSettings — encrypt new settings with CRC32, no command CMAC update.
        let crc = desfire_crc32(&[
            CommandCode::CHANGE_FILE_SETTINGS.as_byte(),
            0x00, // fid
            0x03,
            0xE0,
            0xEE, // comm=encrypt, access=(rw=free,change=key0,read=free,write=free)
        ]);
        let mut plaintext = [0u8; 16];
        plaintext[0] = 0x03;
        plaintext[1] = 0xE0;
        plaintext[2] = 0xEE;
        plaintext[3..7].copy_from_slice(&crc);
        // bytes 7..16 zero-padded

        session.cbc_encrypt_in_place(&mut plaintext).unwrap();
        assert_eq!(
            plaintext,
            [
                0x8E, 0x8C, 0x90, 0xDA, 0x0C, 0x1B, 0x1A, 0x9B, 0x74, 0x90, 0x94, 0xEC, 0xE7, 0x96,
                0x2B, 0x39
            ]
        );

        let mac2 = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();
        assert_eq!(
            mac2.as_bytes(),
            [0x93, 0x91, 0xBB, 0x51, 0x2D, 0x1D, 0x62, 0xC1]
        );
    }

    // Proxmark trace: `hf mfdes createfile --aid 111111 --fid 01 --amode plain --size 000010 -n 0 -t aes`
    //   (backup data file)
    // Session key: 01 02 03 04 B9 C5 B2 72 13 14 15 16 2A F9 A9 10
    // Command: 90 CB 00 00 07 01 00 00 E0 10 00 00 00
    //   fid=0x01, comm_mode=0x00(plain), access=0x00E0, size=0x000010
    // Response: 3D 18 E5 09 38 6A A6 5A 91 00  (8-byte MAC + status OK)
    #[test]
    fn create_backup_data_file_cmac_matches_proxmark_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xB9, 0xC5, 0xB2, 0x72, 0x13, 0x14, 0x15, 0x16, 0x2A, 0xF9,
            0xA9, 0x10,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(
                CommandCode::CREATE_BACKUP_DATA_FILE,
                &[0x01, 0x00, 0x00, 0xE0, 0x10, 0x00, 0x00],
            )
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x3D, 0x18, 0xE5, 0x09, 0x38, 0x6A, 0xA6, 0x5A]
        );
    }

    // Proxmark trace: authenticated plain backup file write then commit
    // Session key: 01 02 03 04 32 D0 98 89 13 14 15 16 36 02 82 D5
    // Step 1 — GetFileSettings fid=0x01:
    //   Command:  90 F5 00 00 01 01 00
    //   Response: 01 00 00 E0 10 00 00 82 CE EF C8 D5 CA EE 72 91 00
    // Step 2 — WriteData fid=0x01, offset=0, length=16:
    //   Command:  90 3D 00 00 17 01 00 00 00 10 00 00 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 00
    //   Response: C1 8B FE 41 A0 60 03 CA 91 00
    // Step 3 — CommitTransaction:
    //   Command:  90 C7 00 00 00 00
    //   Response: A9 B7 49 07 A8 4E 98 B4 91 00
    #[test]
    fn write_and_commit_backup_file_cmac_chain() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x32, 0xD0, 0x98, 0x89, 0x13, 0x14, 0x15, 0x16, 0x36, 0x02,
            0x82, 0xD5,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        // Step 1: GET_FILE_SETTINGS fid=0x01
        session
            .update_command_cmac(CommandCode::GET_FILE_SETTINGS, &[0x01])
            .unwrap();
        let mac1 = session
            .update_response_cmac(
                Status::OperationOk,
                &[0x01, 0x00, 0x00, 0xE0, 0x10, 0x00, 0x00],
            )
            .unwrap();
        assert_eq!(
            mac1.as_bytes(),
            [0x82, 0xCE, 0xEF, 0xC8, 0xD5, 0xCA, 0xEE, 0x72]
        );

        // Step 2: WRITE_DATA fid=0x01, offset=0x000000, length=0x000010, data=00..15
        session
            .update_command_cmac(
                CommandCode::WRITE_DATA,
                &[
                    0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                    0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                ],
            )
            .unwrap();
        let mac2 = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();
        assert_eq!(
            mac2.as_bytes(),
            [0xC1, 0x8B, 0xFE, 0x41, 0xA0, 0x60, 0x03, 0xCA]
        );

        // Step 3: COMMIT_TRANSACTION
        session
            .update_command_cmac(CommandCode::COMMIT_TRANSACTION, &[])
            .unwrap();
        let mac3 = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();
        assert_eq!(
            mac3.as_bytes(),
            [0xA9, 0xB7, 0x49, 0x07, 0xA8, 0x4E, 0x98, 0xB4]
        );
    }

    // Proxmark trace: `hf mfdes createapp --aid 111111 -n 0 -t aes --dstalgo aes --numkeys 1`
    // PICC master key: 00..00 (default AES)
    // Session key reported by proxmark: 01 02 03 04 59 05 6A FD 13 14 15 16 0B A4 CE BF
    // Command: 90 CA 00 00 05 11 11 11 0F 81 00
    // Response: A5 4D BC AE 76 9D 92 D4 91 00  (8-byte MAC + status OK)
    #[test]
    fn create_application_cmac_matches_picc_auth_trace() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x59, 0x05, 0x6A, 0xFD, 0x13, 0x14, 0x15, 0x16, 0x0B, 0xA4,
            0xCE, 0xBF,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        // CMAC state updated for command (MAC not appended to command per DESFire EV1 spec).
        session
            .update_command_cmac(
                CommandCode::CREATE_APPLICATION,
                &[0x11, 0x11, 0x11, 0x0F, 0x81],
            )
            .unwrap();

        // Response MAC over empty body + status 0x00.
        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0xA5, 0x4D, 0xBC, 0xAE, 0x76, 0x9D, 0x92, 0xD4]
        );
    }

    // Proxmark trace: `hf mfdes createapp --keyno 0 --algo 2TDEA --aid 444444 --dstalgo 2TDEA`
    // Session key: 01 02 03 04 36 77 4F CB 01 02 03 04 36 77 4F CB
    // Command: 90 CA 00 00 05 44 44 44 0F 0E 00
    // Tag response: A3 4A DE 4C 38 02 E3 11 91 00
    // Proxmark reported its calculated MAC as C7 24 59 1A 33 9B 23 56.
    #[test]
    fn create_application_2tdea_cmac_matches_proxmark_calculated_mac() {
        let session_key = TwoKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x36, 0x77, 0x4F, 0xCB, 0x01, 0x02, 0x03, 0x04, 0x36, 0x77,
            0x4F, 0xCB,
        ]);
        let mut session = AuthenticatedSession::new_2tdea(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(
                CommandCode::CREATE_APPLICATION,
                &[0x44, 0x44, 0x44, 0x0F, 0x0E],
            )
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0xC7, 0x24, 0x59, 0x1A, 0x33, 0x9B, 0x23, 0x56]
        );
    }

    // Proxmark trace: `hf mfdes createapp --keyno 0 --algo 2TDEA --aid 444444 --dstalgo 2TDEA`
    // Session key: 01 02 03 04 FB 23 ED 16 01 02 03 04 FB 23 ED 16
    // Command: 90 CA 00 00 05 44 44 44 0F 0E 00
    // Response: 25 5C 36 2D 21 49 B2 88 91 00
    #[test]
    fn create_application_2tdea_cmac_matches_successful_tag_trace() {
        let session_key = TwoKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xFB, 0x23, 0xED, 0x16, 0x01, 0x02, 0x03, 0x04, 0xFB, 0x23,
            0xED, 0x16,
        ]);
        let mut session = AuthenticatedSession::new_2tdea(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(
                CommandCode::CREATE_APPLICATION,
                &[0x44, 0x44, 0x44, 0x0F, 0x0E],
            )
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x25, 0x5C, 0x36, 0x2D, 0x21, 0x49, 0xB2, 0x88]
        );
    }

    // Proxmark trace: `hf mfdes createapp --keyno 0 --algo 3TDEA --aid 555555 --dstalgo 3TDEA`
    // Session key: 01 02 03 04 E3 63 90 66 07 08 09 10 D2 E8 98 DE
    //              13 14 15 16 49 D8 C0 2A
    // Command: 90 CA 00 00 05 55 55 55 0F 4E 00
    // Response: 75 DF AA A4 8E CA 79 2A 91 00
    #[test]
    fn create_application_3tdea_cmac_matches_successful_tag_trace() {
        let session_key = ThreeKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xE3, 0x63, 0x90, 0x66, 0x07, 0x08, 0x09, 0x10, 0xD2, 0xE8,
            0x98, 0xDE, 0x13, 0x14, 0x15, 0x16, 0x49, 0xD8, 0xC0, 0x2A,
        ]);
        let mut session = AuthenticatedSession::new_3tdea(KeyNumber::new(0).unwrap(), session_key);

        session
            .update_command_cmac(
                CommandCode::CREATE_APPLICATION,
                &[0x55, 0x55, 0x55, 0x0F, 0x4E],
            )
            .unwrap();

        let response_mac = session
            .update_response_cmac(Status::OperationOk, &[])
            .unwrap();

        assert_eq!(
            response_mac.as_bytes(),
            [0x75, 0xDF, 0xAA, 0xA4, 0x8E, 0xCA, 0x79, 0x2A]
        );
    }
}
