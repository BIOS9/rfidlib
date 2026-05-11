use heapless::Vec;

use crate::mifare::desfire::{
    application::ApplicationId,
    command::{Command, CommandCode},
    crypto::{
        aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, des_cbc_decrypt_in_place,
        des_cbc_encrypt_in_place, desfire_crc16, desfire_crc32, tdes2_cbc_decrypt_in_place,
        tdes2_cbc_encrypt_in_place, tdes3_cbc_decrypt_in_place, tdes3_cbc_encrypt_in_place,
        AesSessionKey, DesSessionKey, RndA, RndA8, RndB, RndB8, ThreeKey3DesSessionKey,
        TwoKey3DesSessionKey,
    },
    error::Error,
    executor::Executor,
    file::{AccessRights, CommunicationMode, FileId, FileSettings},
    framing::FrameCodec,
    key::{KeyNumber, KeySettings},
    session::{AuthenticatedSession, Session},
    status::Status,
    transport::{Transport, MAX_FRAME_SIZE},
    types::U24,
    version::VersionInfo,
};

/// High-level `DESFire` command client.
pub struct Desfire<T, C> {
    executor: Executor<T, C>,
    session: Session,
}

impl<T, C> Desfire<T, C>
where
    T: Transport,
    C: FrameCodec,
{
    /// Creates a client from a byte transport and frame codec.
    pub const fn new(transport: T, codec: C) -> Self {
        Self {
            executor: Executor::new(transport, codec),
            session: Session::Unauthenticated,
        }
    }

    /// Creates a client from an existing executor.
    pub const fn from_executor(executor: Executor<T, C>) -> Self {
        Self {
            executor,
            session: Session::Unauthenticated,
        }
    }

    /// Returns a shared reference to the command executor.
    pub const fn executor(&self) -> &Executor<T, C> {
        &self.executor
    }

    /// Returns a mutable reference to the command executor.
    pub fn executor_mut(&mut self) -> &mut Executor<T, C> {
        &mut self.executor
    }

    /// Consumes the client and returns the command executor.
    pub fn into_executor(self) -> Executor<T, C> {
        self.executor
    }

    /// Current authentication/session state.
    pub const fn session(&self) -> Session {
        self.session
    }

    /// Authenticated session state, when authentication has succeeded.
    pub const fn authenticated_session(&self) -> Option<AuthenticatedSession> {
        match self.session {
            Session::Unauthenticated => None,
            Session::Authenticated(session) => Some(session),
        }
    }

    /// Clears any authenticated session state held by this client.
    pub const fn clear_session(&mut self) {
        self.session = Session::Unauthenticated;
    }

    /// Reads and parses the card version information.
    pub fn get_version(&mut self) -> Result<VersionInfo, Error> {
        let command = Command::new(CommandCode::GET_VERSION, &[])?;
        let mut data: Vec<u8, 28> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        VersionInfo::parse(data.as_slice())
    }

    /// Performs legacy AES authentication with caller-provided reader randomness.
    ///
    /// This stores the session key and initializes secure-messaging state.
    pub fn authenticate_aes_with_rnd_a(
        &mut self,
        key_number: KeyNumber,
        key: &[u8; 16],
        rnd_a: RndA,
    ) -> Result<AuthenticatedSession, Error> {
        let command = Command::new(CommandCode::AUTHENTICATE_AES, &[key_number.as_byte()])?;
        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::AdditionalFrame {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 16 {
            return Err(Error::InvalidResponseLength);
        }

        let encrypted_rnd_b: [u8; 16] = response.data().try_into().expect("length is checked");
        let mut rnd_b_bytes = encrypted_rnd_b;
        aes_cbc_decrypt_in_place(key, &[0u8; 16], &mut rnd_b_bytes);
        let rnd_b = RndB::new(rnd_b_bytes);

        let mut challenge_response = [0u8; 32];
        challenge_response[..16].copy_from_slice(&rnd_a.as_bytes());
        challenge_response[16..].copy_from_slice(&rnd_b.rotate_left());
        aes_cbc_encrypt_in_place(key, &encrypted_rnd_b, &mut challenge_response);

        let response = self.executor.exchange_one(&Command::new(
            CommandCode::ADDITIONAL_FRAME,
            &challenge_response,
        )?)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 16 {
            return Err(Error::InvalidResponseLength);
        }

        let mut returned_rnd_a: [u8; 16] = response.data().try_into().expect("length is checked");
        let response_iv: [u8; 16] = challenge_response[16..32].try_into().expect("valid slice");
        aes_cbc_decrypt_in_place(key, &response_iv, &mut returned_rnd_a);
        if returned_rnd_a != rnd_a.rotate_left() {
            return Err(Error::AuthenticationFailed);
        }

        let session_key = AesSessionKey::derive(rnd_a, rnd_b);
        let session = AuthenticatedSession::new_aes(key_number, session_key);
        self.session = Session::Authenticated(session);
        Ok(session)
    }

    /// Performs 2TDEA (`AUTHENTICATE_ISO`) authentication with caller-provided reader randomness.
    pub fn authenticate_2tdea_with_rnd_a(
        &mut self,
        key_number: KeyNumber,
        key: &[u8; 16],
        rnd_a: RndA8,
    ) -> Result<AuthenticatedSession, Error> {
        let session = self.authenticate_des_family_with_rnd_a(
            CommandCode::AUTHENTICATE_ISO,
            key_number,
            |encrypted_rnd_b, out_rnd_b| {
                tdes2_cbc_decrypt_in_place(key, &[0u8; 8], encrypted_rnd_b);
                out_rnd_b.copy_from_slice(encrypted_rnd_b);
            },
            |rnd_a_bytes, rnd_b_rotated, iv, out| {
                out[..8].copy_from_slice(rnd_a_bytes);
                out[8..16].copy_from_slice(rnd_b_rotated);
                tdes2_cbc_encrypt_in_place(key, iv, out);
            },
            |ciphertext, iv, out| {
                out.copy_from_slice(ciphertext);
                tdes2_cbc_decrypt_in_place(key, iv, out);
            },
            rnd_a,
        )?;
        let session_key = TwoKey3DesSessionKey::derive(session.0, session.1);
        let auth_session = if key[..8] == key[8..] {
            AuthenticatedSession::new_2tdea_with_secure_messaging_key(
                key_number,
                session_key,
                session_key.ev1_des_working_key(),
            )
        } else {
            AuthenticatedSession::new_2tdea(key_number, session_key)
        };
        self.session = Session::Authenticated(auth_session);
        Ok(auth_session)
    }

    /// Performs 3TDEA (`AUTHENTICATE_ISO`) authentication with caller-provided reader randomness.
    pub fn authenticate_3tdea_with_rnd_a(
        &mut self,
        key_number: KeyNumber,
        key: &[u8; 24],
        rnd_a: RndA,
    ) -> Result<AuthenticatedSession, Error> {
        let command = Command::new(CommandCode::AUTHENTICATE_ISO, &[key_number.as_byte()])?;
        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::AdditionalFrame {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 16 {
            return Err(Error::InvalidResponseLength);
        }

        let encrypted_rnd_b: [u8; 16] = response.data().try_into().expect("length is checked");
        let mut rnd_b_bytes = encrypted_rnd_b;
        tdes3_cbc_decrypt_in_place(key, &[0u8; 8], &mut rnd_b_bytes);
        let rnd_b = RndB::new(rnd_b_bytes);

        let mut challenge_response = [0u8; 32];
        challenge_response[..16].copy_from_slice(&rnd_a.as_bytes());
        challenge_response[16..].copy_from_slice(&rnd_b.rotate_left());
        let challenge_iv: [u8; 8] = encrypted_rnd_b[8..16].try_into().expect("valid slice");
        tdes3_cbc_encrypt_in_place(key, &challenge_iv, &mut challenge_response);

        let response = self.executor.exchange_one(&Command::new(
            CommandCode::ADDITIONAL_FRAME,
            &challenge_response,
        )?)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 16 {
            return Err(Error::InvalidResponseLength);
        }

        let mut returned_rnd_a: [u8; 16] = response.data().try_into().expect("length is checked");
        let response_iv: [u8; 8] = challenge_response[24..32].try_into().expect("valid slice");
        tdes3_cbc_decrypt_in_place(key, &response_iv, &mut returned_rnd_a);
        if returned_rnd_a != rnd_a.rotate_left() {
            return Err(Error::AuthenticationFailed);
        }

        let session_key = ThreeKey3DesSessionKey::derive(rnd_a, rnd_b);
        let auth_session = AuthenticatedSession::new_3tdea(key_number, session_key);
        self.session = Session::Authenticated(auth_session);
        Ok(auth_session)
    }

    /// Performs legacy DES (`AUTHENTICATE_LEGACY`) authentication with caller-provided reader randomness.
    pub fn authenticate_des_with_rnd_a(
        &mut self,
        key_number: KeyNumber,
        key: &[u8; 8],
        rnd_a: RndA8,
    ) -> Result<AuthenticatedSession, Error> {
        let session = self.authenticate_des_family_with_rnd_a(
            CommandCode::AUTHENTICATE_LEGACY,
            key_number,
            |encrypted_rnd_b, out_rnd_b| {
                des_cbc_decrypt_in_place(key, &[0u8; 8], encrypted_rnd_b);
                out_rnd_b.copy_from_slice(encrypted_rnd_b);
            },
            |rnd_a_bytes, rnd_b_rotated, iv, out| {
                out[..8].copy_from_slice(rnd_a_bytes);
                out[8..16].copy_from_slice(rnd_b_rotated);
                des_cbc_encrypt_in_place(key, iv, out);
            },
            |ciphertext, iv, out| {
                out.copy_from_slice(ciphertext);
                des_cbc_decrypt_in_place(key, iv, out);
            },
            rnd_a,
        )?;
        let session_key = DesSessionKey::derive(session.0, session.1);
        let auth_session = AuthenticatedSession::new_des(key_number, session_key);
        self.session = Session::Authenticated(auth_session);
        Ok(auth_session)
    }

    /// Common DES-family authentication handshake.
    ///
    /// Returns `(RndA, RndB)` for session key derivation.
    fn authenticate_des_family_with_rnd_a(
        &mut self,
        command_code: CommandCode,
        key_number: KeyNumber,
        decrypt_rnd_b: impl Fn(&mut [u8; 8], &mut [u8; 8]),
        encrypt_challenge: impl Fn(&[u8; 8], &[u8; 8], &[u8; 8], &mut [u8; 16]),
        decrypt_rnd_a_prime: impl Fn(&[u8; 8], &[u8; 8], &mut [u8; 8]),
        rnd_a: RndA8,
    ) -> Result<(RndA8, RndB8), Error> {
        let command = Command::new(command_code, &[key_number.as_byte()])?;
        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::AdditionalFrame {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 8 {
            return Err(Error::InvalidResponseLength);
        }

        let mut enc_rnd_b: [u8; 8] = response.data().try_into().expect("length is checked");
        let original_enc_rnd_b = enc_rnd_b;
        let mut rnd_b_bytes = [0u8; 8];
        decrypt_rnd_b(&mut enc_rnd_b, &mut rnd_b_bytes);
        let rnd_b = RndB8::new(rnd_b_bytes);

        let mut challenge_response = [0u8; 16];
        encrypt_challenge(
            &rnd_a.as_bytes(),
            &rnd_b.rotate_left(),
            &original_enc_rnd_b,
            &mut challenge_response,
        );

        let response = self.executor.exchange_one(&Command::new(
            CommandCode::ADDITIONAL_FRAME,
            &challenge_response,
        )?)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() != 8 {
            return Err(Error::InvalidResponseLength);
        }

        // IV for final decryption = last 8 bytes of challenge_response.
        let response_iv: [u8; 8] = challenge_response[8..16].try_into().expect("valid slice");
        let mut returned_rnd_a = [0u8; 8];
        let mut enc_rnd_a: [u8; 8] = response.data().try_into().expect("length is checked");
        decrypt_rnd_a_prime(&mut enc_rnd_a, &response_iv, &mut returned_rnd_a);
        if returned_rnd_a != rnd_a.rotate_left() {
            return Err(Error::AuthenticationFailed);
        }

        Ok((rnd_a, rnd_b))
    }

    /// Reads key settings for the currently selected application.
    pub fn get_key_settings(&mut self) -> Result<KeySettings, Error> {
        let command = Command::new(CommandCode::GET_KEY_SETTINGS, &[])?;
        let mut data: Vec<u8, 2> = Vec::new();

        if matches!(self.session, Session::Authenticated(_)) {
            self.execute_single_maced(&command, &mut data)?;
        } else {
            self.executor.execute(&command, &mut data)?;
        }

        KeySettings::parse(data.as_slice())
    }

    /// Reads one key version from the currently selected application.
    pub fn get_key_version(&mut self, key_number: KeyNumber) -> Result<u8, Error> {
        let command = Command::new(CommandCode::GET_KEY_VERSION, &[key_number.as_byte()])?;
        let mut data: Vec<u8, 1> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        data.first().copied().ok_or(Error::InvalidResponseLength)
    }

    /// Changes a key in the currently selected application.
    ///
    /// `key_version` is the AES key version byte stored alongside the key on the card.
    ///
    /// When changing the key that was used for authentication, the card invalidates the
    /// session on success and the client returns to unauthenticated state.
    ///
    /// When changing a different key, `old_key` must be the current value of that key slot.
    /// The card returns an 8-byte response MAC and the session remains active.
    pub fn change_key_aes(
        &mut self,
        key_number: KeyNumber,
        new_key: [u8; 16],
        key_version: u8,
        old_key: Option<[u8; 16]>,
    ) -> Result<(), Error> {
        let changing_auth_key = match self.session {
            Session::Authenticated(s) => key_number == s.key_number(),
            Session::Unauthenticated => return Err(Error::MissingAuthentication),
        };
        self.change_key_aes_impl(
            key_number.as_byte(),
            new_key,
            key_version,
            old_key,
            changing_auth_key,
        )
    }

    /// Changes the PICC master key (app 0x000000 must be selected).
    ///
    /// The `KeyNo` byte for a PICC-level AES key encodes the algorithm (`0x80`) rather than a
    /// slot number. Callers must authenticate with the current PICC master key before calling
    /// this; the card invalidates the session on success.
    pub fn change_picc_key_aes(&mut self, new_key: [u8; 16], key_version: u8) -> Result<(), Error> {
        // 0x80 = AES algorithm flag for PICC-level key change; always same-key case.
        self.change_key_aes_impl(0x80, new_key, key_version, None, true)
    }

    fn change_key_aes_impl(
        &mut self,
        key_no_byte: u8,
        new_key: [u8; 16],
        key_version: u8,
        old_key: Option<[u8; 16]>,
        changing_auth_key: bool,
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        let mut plaintext: Vec<u8, MAX_FRAME_SIZE> = Vec::new();

        if changing_auth_key {
            // CRC32 over [cmd_code || key_no || new_key || key_version].
            let mut crc_input: Vec<u8, 19> = Vec::new();
            crc_input
                .push(CommandCode::CHANGE_KEY.as_byte())
                .map_err(|_| Error::CommandTooLong)?;
            crc_input
                .push(key_no_byte)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input
                .extend_from_slice(&new_key)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input
                .push(key_version)
                .map_err(|_| Error::CommandTooLong)?;
            let crc = desfire_crc32(crc_input.as_slice());

            // Plaintext: [new_key || key_version || CRC32 || zero_padding].
            plaintext
                .extend_from_slice(&new_key)
                .map_err(|_| Error::CommandTooLong)?;
            plaintext
                .push(key_version)
                .map_err(|_| Error::CommandTooLong)?;
            plaintext
                .extend_from_slice(&crc)
                .map_err(|_| Error::CommandTooLong)?;
        } else {
            let old = old_key.ok_or(Error::MissingOldKey)?;
            let key_xor: [u8; 16] = core::array::from_fn(|i| new_key[i] ^ old[i]);

            // CRC32_a over [cmd_code || key_no || (new_key XOR old_key) || key_version].
            // CRC32_b over [new_key] only (no version byte).
            let mut crc_input_a: Vec<u8, 19> = Vec::new();
            crc_input_a
                .push(CommandCode::CHANGE_KEY.as_byte())
                .map_err(|_| Error::CommandTooLong)?;
            crc_input_a
                .push(key_no_byte)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input_a
                .extend_from_slice(&key_xor)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input_a
                .push(key_version)
                .map_err(|_| Error::CommandTooLong)?;
            let crc_a = desfire_crc32(crc_input_a.as_slice());
            let crc_b = desfire_crc32(&new_key);

            // Plaintext: [(new_key XOR old_key) || key_version || CRC32_a || CRC32_b || zero_padding].
            plaintext
                .extend_from_slice(&key_xor)
                .map_err(|_| Error::CommandTooLong)?;
            plaintext
                .push(key_version)
                .map_err(|_| Error::CommandTooLong)?;
            plaintext
                .extend_from_slice(&crc_a)
                .map_err(|_| Error::CommandTooLong)?;
            plaintext
                .extend_from_slice(&crc_b)
                .map_err(|_| Error::CommandTooLong)?;
        }

        // Zero-pad to block boundary.
        let block_size = session.block_size();
        while !plaintext.len().is_multiple_of(block_size) {
            plaintext.push(0x00).map_err(|_| Error::CommandTooLong)?;
        }

        // Encrypt using current chaining IV; chaining advances to last ciphertext block.
        session.cbc_encrypt_in_place(plaintext.as_mut_slice())?;

        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .push(key_no_byte)
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(plaintext.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::CHANGE_KEY, cmd_data.as_slice())?;

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        if changing_auth_key {
            // Card invalidates the session after changing the authenticated key.
            self.session = Session::Unauthenticated;
        } else {
            // Response carries 8-byte MAC over empty body.
            verify_response_mac(&mut session, Status::OperationOk, response.data())?;
            self.session = Session::Authenticated(session);
        }

        Ok(())
    }

    /// Changes a DES application key slot (8-byte key).
    ///
    /// When changing a key other than the session key, `old_key` must hold the current value of
    /// that slot. When changing the session key itself (`old_key` is unused in that case),
    /// the card invalidates the session on success.
    pub fn change_key_des(
        &mut self,
        key_number: KeyNumber,
        new_key: [u8; 8],
        old_key: Option<[u8; 8]>,
    ) -> Result<(), Error> {
        let changing_auth_key = match self.session {
            Session::Authenticated(s) => key_number == s.key_number(),
            Session::Unauthenticated => return Err(Error::MissingAuthentication),
        };
        self.change_key_legacy_impl(
            key_number.as_byte(),
            &new_key,
            old_key.as_ref().map(<[u8; 8]>::as_slice),
            changing_auth_key,
        )
    }

    /// Changes a two-key 3DES (2TDEA) application key slot (16-byte key).
    ///
    /// When changing a key other than the session key, `old_key` must hold the current value of
    /// that slot. When changing the session key itself, the card invalidates the session on
    /// success.
    pub fn change_key_2tdea(
        &mut self,
        key_number: KeyNumber,
        new_key: [u8; 16],
        old_key: Option<[u8; 16]>,
    ) -> Result<(), Error> {
        let changing_auth_key = match self.session {
            Session::Authenticated(s) => key_number == s.key_number(),
            Session::Unauthenticated => return Err(Error::MissingAuthentication),
        };
        self.change_key_legacy_impl(
            key_number.as_byte(),
            &new_key,
            old_key.as_ref().map(<[u8; 16]>::as_slice),
            changing_auth_key,
        )
    }

    /// Changes a three-key 3DES (3TDEA) application key slot (24-byte key).
    ///
    /// When changing a key other than the session key, `old_key` must hold the current value of
    /// that slot. When changing the session key itself, the card invalidates the session on
    /// success.
    pub fn change_key_3tdea(
        &mut self,
        key_number: KeyNumber,
        new_key: [u8; 24],
        old_key: Option<[u8; 24]>,
    ) -> Result<(), Error> {
        let changing_auth_key = match self.session {
            Session::Authenticated(s) => key_number == s.key_number(),
            Session::Unauthenticated => return Err(Error::MissingAuthentication),
        };
        self.change_key_legacy_impl(
            key_number.as_byte(),
            &new_key,
            old_key.as_ref().map(<[u8; 24]>::as_slice),
            changing_auth_key,
        )
    }

    /// Changes the PICC master key to a new two-key 3DES (2TDEA) key.
    ///
    /// `KeyNo` byte `0x00` signals DES/2TDEA at PICC level. The card invalidates the session on
    /// success. Caller must be authenticated with the current PICC master key.
    pub fn change_picc_key_2tdea(&mut self, new_key: [u8; 16]) -> Result<(), Error> {
        self.change_key_legacy_impl(0x00, &new_key, None, true)
    }

    /// Changes the PICC master key to a new three-key 3DES (3TDEA) key.
    ///
    /// `KeyNo` byte `0x40` signals 3TDEA at PICC level. The card invalidates the session on
    /// success. Caller must be authenticated with the current PICC master key.
    pub fn change_picc_key_3tdea(&mut self, new_key: [u8; 24]) -> Result<(), Error> {
        self.change_key_legacy_impl(0x40, &new_key, None, true)
    }

    fn change_key_legacy_impl(
        &mut self,
        key_no_byte: u8,
        new_key: &[u8],
        old_key: Option<&[u8]>,
        changing_auth_key: bool,
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        let use_crc32 = session.encrypted_command_crc_size() == 4;
        let mut plaintext: Vec<u8, MAX_FRAME_SIZE> = Vec::new();

        if changing_auth_key {
            // Same-key: [new_key || CRC(cmd || key_no || new_key)] zero-padded to block.
            let mut crc_input: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
            crc_input
                .push(CommandCode::CHANGE_KEY.as_byte())
                .map_err(|_| Error::CommandTooLong)?;
            crc_input
                .push(key_no_byte)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input
                .extend_from_slice(new_key)
                .map_err(|_| Error::CommandTooLong)?;

            plaintext
                .extend_from_slice(new_key)
                .map_err(|_| Error::CommandTooLong)?;
            if use_crc32 {
                plaintext
                    .extend_from_slice(&desfire_crc32(crc_input.as_slice()))
                    .map_err(|_| Error::CommandTooLong)?;
            } else {
                plaintext
                    .extend_from_slice(&desfire_crc16(crc_input.as_slice()))
                    .map_err(|_| Error::CommandTooLong)?;
            }
        } else {
            let old = old_key.ok_or(Error::MissingOldKey)?;

            // key_xor = new_key XOR old_key.
            let mut key_xor: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
            for (n, o) in new_key.iter().zip(old.iter()) {
                key_xor.push(n ^ o).map_err(|_| Error::CommandTooLong)?;
            }

            // CRC_a over [cmd || key_no || key_xor]; CRC_b over [new_key].
            let mut crc_input_a: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
            crc_input_a
                .push(CommandCode::CHANGE_KEY.as_byte())
                .map_err(|_| Error::CommandTooLong)?;
            crc_input_a
                .push(key_no_byte)
                .map_err(|_| Error::CommandTooLong)?;
            crc_input_a
                .extend_from_slice(key_xor.as_slice())
                .map_err(|_| Error::CommandTooLong)?;

            // Plaintext: [key_xor || CRC_a || CRC_b] zero-padded to block.
            plaintext
                .extend_from_slice(key_xor.as_slice())
                .map_err(|_| Error::CommandTooLong)?;
            if use_crc32 {
                plaintext
                    .extend_from_slice(&desfire_crc32(crc_input_a.as_slice()))
                    .map_err(|_| Error::CommandTooLong)?;
                plaintext
                    .extend_from_slice(&desfire_crc32(new_key))
                    .map_err(|_| Error::CommandTooLong)?;
            } else {
                plaintext
                    .extend_from_slice(&desfire_crc16(crc_input_a.as_slice()))
                    .map_err(|_| Error::CommandTooLong)?;
                plaintext
                    .extend_from_slice(&desfire_crc16(new_key))
                    .map_err(|_| Error::CommandTooLong)?;
            }
        }

        // Zero-pad to block boundary.
        let block_size = session.block_size();
        while !plaintext.len().is_multiple_of(block_size) {
            plaintext.push(0x00).map_err(|_| Error::CommandTooLong)?;
        }

        // Encrypt using current chaining IV; chaining advances to last ciphertext block.
        session.cbc_encrypt_in_place(plaintext.as_mut_slice())?;

        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .push(key_no_byte)
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(plaintext.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::CHANGE_KEY, cmd_data.as_slice())?;

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        if changing_auth_key {
            self.session = Session::Unauthenticated;
        } else {
            verify_response_mac(&mut session, Status::OperationOk, response.data())?;
            self.session = Session::Authenticated(session);
        }

        Ok(())
    }

    /// Reads available free memory, when supported by the card.
    pub fn free_memory(&mut self) -> Result<U24, Error> {
        let command = Command::new(CommandCode::FREE_MEM, &[])?;
        let mut data: Vec<u8, 3> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        let bytes = data
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidResponseLength)?;
        Ok(U24::from_le_bytes(bytes))
    }

    /// Selects an application by `DESFire` AID.
    pub fn select_application(&mut self, application_id: ApplicationId) -> Result<(), Error> {
        let command = Command::new(CommandCode::SELECT_APPLICATION, &application_id.as_bytes())?;
        let mut data: Vec<u8, 0> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        self.clear_session();
        Ok(())
    }

    /// Reads all application identifiers returned by the card.
    pub fn get_application_ids<const N: usize>(
        &mut self,
        application_ids: &mut Vec<ApplicationId, N>,
    ) -> Result<(), Error> {
        let command = Command::new(CommandCode::GET_APPLICATION_IDS, &[])?;
        let mut data: Vec<u8, 252> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        parse_application_ids(data.as_slice(), application_ids)
    }

    /// Commits all pending changes in the current transaction.
    ///
    /// Required after writing to backup data files or record files to make
    /// changes permanent. Without commit the card discards the writes on
    /// the next `SelectApplication` or power cycle.
    pub fn commit_transaction(&mut self) -> Result<(), Error> {
        let command = Command::new(CommandCode::COMMIT_TRANSACTION, &[])?;
        self.execute_management_command(&command)
    }

    /// Aborts all pending changes in the current transaction.
    ///
    /// Discards any writes to backup data files or record files since the
    /// last commit.
    pub fn abort_transaction(&mut self) -> Result<(), Error> {
        let command = Command::new(CommandCode::ABORT_TRANSACTION, &[])?;
        self.execute_management_command(&command)
    }

    /// Formats the PICC, wiping all applications and reclaiming all memory.
    ///
    /// Requires prior authentication with the PICC master key.
    pub fn format_picc(&mut self) -> Result<(), Error> {
        let command = Command::new(CommandCode::FORMAT_PICC, &[])?;
        self.execute_management_command(&command)
    }

    /// Creates a new application.
    pub fn create_application(
        &mut self,
        application_id: ApplicationId,
        key_settings: KeySettings,
    ) -> Result<(), Error> {
        let mut payload: Vec<u8, 5> = Vec::new();
        payload
            .extend_from_slice(&application_id.as_bytes())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .push(key_settings.raw_settings())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .push(key_settings.raw_key_count())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::CREATE_APPLICATION, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Deletes an application and all its files.
    pub fn delete_application(&mut self, application_id: ApplicationId) -> Result<(), Error> {
        let command = Command::new(CommandCode::DELETE_APPLICATION, &application_id.as_bytes())?;
        self.execute_management_command(&command)
    }

    /// Reads all file identifiers in the selected application.
    pub fn get_file_ids<const N: usize>(
        &mut self,
        file_ids: &mut Vec<FileId, N>,
    ) -> Result<(), Error> {
        let command = Command::new(CommandCode::GET_FILE_IDS, &[])?;
        let mut data: Vec<u8, 32> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        parse_file_ids(data.as_slice(), file_ids)
    }

    /// Reads and parses settings for one file in the selected application.
    pub fn get_file_settings(&mut self, file_id: FileId) -> Result<FileSettings, Error> {
        let command = Command::new(CommandCode::GET_FILE_SETTINGS, &[file_id.as_byte()])?;
        let mut data: Vec<u8, 32> = Vec::new();

        if matches!(self.session, Session::Authenticated(_)) {
            self.execute_single_maced(&command, &mut data)?;
        } else {
            self.executor.execute(&command, &mut data)?;
        }

        FileSettings::parse(data.as_slice())
    }

    /// Changes the communication mode and access rights of a file.
    ///
    /// Requires authentication. New settings are sent encrypted with CRC32 using the current
    /// session chaining IV (same pattern as enciphered writes — no command CMAC update).
    pub fn change_file_settings(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        let ar = access_rights.to_bytes();
        let new_settings = [u8::from(communication_mode), ar[0], ar[1]];

        // CRC covers [cmd_code || fid || new_settings].
        let mut crc_input: Vec<u8, 5> = Vec::new();
        crc_input
            .push(CommandCode::CHANGE_FILE_SETTINGS.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        crc_input
            .push(file_id.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        crc_input
            .extend_from_slice(&new_settings)
            .map_err(|_| Error::CommandTooLong)?;

        let block_size = session.block_size();
        let mut plaintext: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        plaintext
            .extend_from_slice(&new_settings)
            .map_err(|_| Error::CommandTooLong)?;
        extend_desfire_crc(
            &mut plaintext,
            crc_input.as_slice(),
            session.encrypted_command_crc_size(),
        )?;
        while !plaintext.len().is_multiple_of(block_size) {
            plaintext.push(0x00).map_err(|_| Error::CommandTooLong)?;
        }

        // Encrypts in place using current chaining IV; chaining advances to last ciphertext block.
        session.cbc_encrypt_in_place(plaintext.as_mut_slice())?;

        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .push(file_id.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(plaintext.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::CHANGE_FILE_SETTINGS, cmd_data.as_slice())?;

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        verify_response_mac(&mut session, Status::OperationOk, response.data())?;
        self.session = Session::Authenticated(session);
        Ok(())
    }

    /// Reads and MAC-verifies bytes from a `MACed` standard or backup data file.
    pub fn read_data_maced<const N: usize>(
        &mut self,
        file_id: FileId,
        offset: U24,
        length: U24,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        let command_data = read_data_command_data(file_id, offset, length)?;
        let command = Command::new(CommandCode::READ_DATA, command_data.as_slice())?;
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        session.update_command_cmac(command.code(), command.data())?;

        let mut raw: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        self.executor.execute(&command, &mut raw)?;

        let body = verify_response_mac(&mut session, Status::OperationOk, raw.as_slice())?;
        data.clear();
        data.extend_from_slice(body)
            .map_err(|_| Error::ResponseTooLong)?;

        self.session = Session::Authenticated(session);
        Ok(())
    }

    /// Reads bytes from a standard or backup data file.
    pub fn read_data<const N: usize>(
        &mut self,
        file_id: FileId,
        offset: U24,
        length: U24,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        let command_data = read_data_command_data(file_id, offset, length)?;
        let command = Command::new(CommandCode::READ_DATA, command_data.as_slice())?;
        self.executor.execute(&command, data)
    }

    /// Reads and decrypts bytes from an enciphered standard or backup data file.
    ///
    /// A `length` of zero is passed through to the card and the plaintext length
    /// is inferred from the encrypted response CRC and zero padding.
    pub fn read_data_enciphered<const N: usize>(
        &mut self,
        file_id: FileId,
        offset: U24,
        length: U24,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        let command_data = read_data_command_data(file_id, offset, length)?;
        let command = Command::new(CommandCode::READ_DATA, command_data.as_slice())?;
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        #[allow(unused_variables)]
        // The cmac value is not used in nostd due to the logging call below
        session.update_command_cmac(command.code(), command.data())?;

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }
        let block_size = session.block_size();
        if response.data().len() < block_size || response.data().len() % block_size != 0 {
            return Err(Error::InvalidResponseLength);
        }

        let mut decrypted: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        decrypted
            .extend_from_slice(response.data())
            .map_err(|_| Error::ResponseTooLong)?;

        // Decrypts in place using current chaining IV and updates chaining state to last ciphertext block.
        session.cbc_decrypt_in_place(decrypted.as_mut_slice())?;

        let crc_size = session.encrypted_read_crc_size();
        let plaintext_len = encrypted_read_plaintext_len(
            decrypted.as_slice(),
            usize::try_from(length.as_u32()).expect("U24 fits in usize"),
            response.status(),
            crc_size,
        )?;

        data.clear();
        data.extend_from_slice(&decrypted.as_slice()[..plaintext_len])
            .map_err(|_| Error::ResponseTooLong)?;

        self.session = Session::Authenticated(session);
        Ok(())
    }

    /// Writes bytes to a plain standard or backup data file.
    pub fn write_data(&mut self, file_id: FileId, offset: U24, data: &[u8]) -> Result<(), Error> {
        let header = write_data_command_header(file_id, offset, data)?;
        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .extend_from_slice(header.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::WRITE_DATA, cmd_data.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Writes and `MAC`-signs bytes to a `MACed` standard or backup data file.
    pub fn write_data_maced(
        &mut self,
        file_id: FileId,
        offset: U24,
        data: &[u8],
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        let header = write_data_command_header(file_id, offset, data)?;

        // CMAC covers [cmd_code || header || data].
        let mut cmac_payload: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmac_payload
            .extend_from_slice(header.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        cmac_payload
            .extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        let mac = session.update_command_cmac(CommandCode::WRITE_DATA, cmac_payload.as_slice())?;

        // Build command: [header || data || MAC].
        cmac_payload
            .extend_from_slice(&mac.as_bytes())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::WRITE_DATA, cmac_payload.as_slice())?;
        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        verify_response_mac(&mut session, Status::OperationOk, response.data())?;
        self.session = Session::Authenticated(session);
        Ok(())
    }

    /// Writes and encrypts bytes to an enciphered standard or backup data file.
    pub fn write_data_enciphered(
        &mut self,
        file_id: FileId,
        offset: U24,
        data: &[u8],
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        let header = write_data_command_header(file_id, offset, data)?;

        // IV = current chaining state (no command CMAC update for enciphered writes).
        // CRC covers the full command payload: [cmd_code || header || data].
        // Plaintext: [data || CRC(cmd_code||header||data)] zero-padded to block boundary
        // (ISO 9797-1 method 1 — no 0x80 terminator).
        let mut crc_input: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        crc_input
            .push(CommandCode::WRITE_DATA.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        crc_input
            .extend_from_slice(header.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        crc_input
            .extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        let crc_size = session.encrypted_command_crc_size();

        let block_size = session.block_size();
        let mut plaintext: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        plaintext
            .extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        extend_desfire_crc(&mut plaintext, crc_input.as_slice(), crc_size)?;
        while !plaintext.len().is_multiple_of(block_size) {
            plaintext.push(0x00).map_err(|_| Error::CommandTooLong)?;
        }

        // Encrypts in place using current chaining IV and updates chaining state to last ciphertext block.
        session.cbc_encrypt_in_place(plaintext.as_mut_slice())?;

        // Build command: [header || ciphertext].
        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .extend_from_slice(header.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(plaintext.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::WRITE_DATA, cmd_data.as_slice())?;

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        verify_response_mac(&mut session, Status::OperationOk, response.data())?;
        self.session = Session::Authenticated(session);
        Ok(())
    }

    /// Creates a standard data file in the selected application.
    pub fn create_std_data_file(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        size: U24,
    ) -> Result<(), Error> {
        let payload = create_data_file_payload(file_id, communication_mode, access_rights, size)?;
        let command = Command::new(CommandCode::CREATE_STD_DATA_FILE, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Creates a backup data file in the selected application.
    pub fn create_backup_data_file(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        size: U24,
    ) -> Result<(), Error> {
        let payload = create_data_file_payload(file_id, communication_mode, access_rights, size)?;
        let command = Command::new(CommandCode::CREATE_BACKUP_DATA_FILE, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Creates a value file in the selected application.
    #[allow(clippy::too_many_arguments)]
    pub fn create_value_file(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        lower_limit: i32,
        upper_limit: i32,
        initial_value: i32,
        limited_credit_enabled: bool,
    ) -> Result<(), Error> {
        let ar = access_rights.to_bytes();
        let mut payload: Vec<u8, 17> = Vec::new();
        payload
            .push(file_id.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .push(u8::from(communication_mode))
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .extend_from_slice(&ar)
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .extend_from_slice(&lower_limit.to_le_bytes())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .extend_from_slice(&upper_limit.to_le_bytes())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .extend_from_slice(&initial_value.to_le_bytes())
            .map_err(|_| Error::CommandTooLong)?;
        payload
            .push(u8::from(limited_credit_enabled))
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::CREATE_VALUE_FILE, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Creates a linear record file in the selected application.
    pub fn create_linear_record_file(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        record_size: U24,
        max_records: U24,
    ) -> Result<(), Error> {
        let payload = create_record_file_payload(
            file_id,
            communication_mode,
            access_rights,
            record_size,
            max_records,
        )?;
        let command = Command::new(CommandCode::CREATE_LINEAR_RECORD_FILE, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Creates a cyclic record file in the selected application.
    pub fn create_cyclic_record_file(
        &mut self,
        file_id: FileId,
        communication_mode: CommunicationMode,
        access_rights: AccessRights,
        record_size: U24,
        max_records: U24,
    ) -> Result<(), Error> {
        let payload = create_record_file_payload(
            file_id,
            communication_mode,
            access_rights,
            record_size,
            max_records,
        )?;
        let command = Command::new(CommandCode::CREATE_CYCLIC_RECORD_FILE, payload.as_slice())?;
        self.execute_management_command(&command)
    }

    /// Deletes a file from the selected application.
    pub fn delete_file(&mut self, file_id: FileId) -> Result<(), Error> {
        let command = Command::new(CommandCode::DELETE_FILE, &[file_id.as_byte()])?;
        self.execute_management_command(&command)
    }

    /// Sends a management command (create/delete application or file).
    ///
    /// When authenticated the card returns an 8-byte response MAC that must be
    /// verified and the session CMAC state updated. When unauthenticated the
    /// card returns only a status byte with no MAC.
    fn execute_management_command(&mut self, command: &Command) -> Result<(), Error> {
        match self.session {
            Session::Authenticated(mut session) => {
                session.update_command_cmac(command.code(), command.data())?;
                let response = self.executor.exchange_one(command)?;
                if response.status() != Status::OperationOk {
                    return Err(Error::Status(response.status()));
                }
                verify_response_mac(&mut session, Status::OperationOk, response.data())?;
                self.session = Session::Authenticated(session);
            }
            Session::Unauthenticated => {
                let mut data: Vec<u8, 0> = Vec::new();
                self.executor.execute(command, &mut data)?;
            }
        }
        Ok(())
    }

    fn execute_single_maced<const N: usize>(
        &mut self,
        command: &Command,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        let Session::Authenticated(mut session) = self.session else {
            return Err(Error::MissingAuthentication);
        };

        session.update_command_cmac(command.code(), command.data())?;
        let response = self.executor.exchange_one(command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        let body = verify_response_mac(&mut session, response.status(), response.data())?;
        data.clear();
        data.extend_from_slice(body)
            .map_err(|_| Error::ResponseTooLong)?;

        self.session = Session::Authenticated(session);
        Ok(())
    }
}

fn create_data_file_payload(
    file_id: FileId,
    communication_mode: CommunicationMode,
    access_rights: AccessRights,
    size: U24,
) -> Result<Vec<u8, 7>, Error> {
    let ar = access_rights.to_bytes();
    let mut payload: Vec<u8, 7> = Vec::new();
    payload
        .push(file_id.as_byte())
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .push(u8::from(communication_mode))
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .extend_from_slice(&ar)
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .extend_from_slice(&size.to_le_bytes())
        .map_err(|_| Error::CommandTooLong)?;
    Ok(payload)
}

fn create_record_file_payload(
    file_id: FileId,
    communication_mode: CommunicationMode,
    access_rights: AccessRights,
    record_size: U24,
    max_records: U24,
) -> Result<Vec<u8, 10>, Error> {
    let ar = access_rights.to_bytes();
    let mut payload: Vec<u8, 10> = Vec::new();
    payload
        .push(file_id.as_byte())
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .push(u8::from(communication_mode))
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .extend_from_slice(&ar)
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .extend_from_slice(&record_size.to_le_bytes())
        .map_err(|_| Error::CommandTooLong)?;
    payload
        .extend_from_slice(&max_records.to_le_bytes())
        .map_err(|_| Error::CommandTooLong)?;
    Ok(payload)
}

fn write_data_command_header(
    file_id: FileId,
    offset: U24,
    data: &[u8],
) -> Result<Vec<u8, 7>, Error> {
    let length = u32::try_from(data.len())
        .ok()
        .and_then(U24::new)
        .ok_or(Error::CommandTooLong)?;
    read_data_command_data(file_id, offset, length)
}

fn read_data_command_data(file_id: FileId, offset: U24, length: U24) -> Result<Vec<u8, 7>, Error> {
    let mut command_data: Vec<u8, 7> = Vec::new();
    command_data
        .push(file_id.as_byte())
        .map_err(|_| Error::CommandTooLong)?;
    command_data
        .extend_from_slice(&offset.to_le_bytes())
        .map_err(|_| Error::CommandTooLong)?;
    command_data
        .extend_from_slice(&length.to_le_bytes())
        .map_err(|_| Error::CommandTooLong)?;
    Ok(command_data)
}

fn verify_response_mac<'a>(
    session: &mut AuthenticatedSession,
    status: Status,
    data: &'a [u8],
) -> Result<&'a [u8], Error> {
    let mac_len = session.mac_len();
    if data.len() < mac_len {
        return Err(Error::InvalidResponseLength);
    }

    let (body, received) = data.split_at(data.len() - mac_len);
    let expected = session.update_response_cmac(status, body)?;
    if expected.as_bytes()[..mac_len] != *received {
        return Err(Error::InvalidMac);
    }

    Ok(body)
}

fn encrypted_read_plaintext_len(
    decrypted: &[u8],
    requested_length: usize,
    status: Status,
    crc_size: usize,
) -> Result<usize, Error> {
    if requested_length == 0 {
        return infer_encrypted_read_plaintext_len(decrypted, status, crc_size);
    }

    validate_encrypted_read_plaintext_len(decrypted, requested_length, status, crc_size)
}

fn infer_encrypted_read_plaintext_len(
    decrypted: &[u8],
    status: Status,
    crc_size: usize,
) -> Result<usize, Error> {
    for plaintext_len in (0..=decrypted.len().saturating_sub(crc_size)).rev() {
        if validate_encrypted_read_plaintext_len(decrypted, plaintext_len, status, crc_size).is_ok()
        {
            return Ok(plaintext_len);
        }
    }

    Err(Error::InvalidCrc)
}

fn validate_encrypted_read_plaintext_len(
    decrypted: &[u8],
    plaintext_len: usize,
    status: Status,
    crc_size: usize,
) -> Result<usize, Error> {
    let crc_start = plaintext_len;
    let crc_end = crc_start + crc_size;
    if crc_end > decrypted.len() {
        return Err(Error::InvalidResponseLength);
    }

    if !has_valid_encrypted_response_padding(&decrypted[crc_end..]) {
        return Err(Error::InvalidPadding);
    }

    let mut crc_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
    crc_data
        .extend_from_slice(&decrypted[..plaintext_len])
        .map_err(|_| Error::ResponseTooLong)?;
    crc_data
        .push(status.as_byte())
        .map_err(|_| Error::ResponseTooLong)?;

    if !desfire_crc_matches(crc_data.as_slice(), &decrypted[crc_start..crc_end]) {
        return Err(Error::InvalidCrc);
    }

    Ok(plaintext_len)
}

fn extend_desfire_crc<const N: usize>(
    out: &mut Vec<u8, N>,
    data: &[u8],
    crc_size: usize,
) -> Result<(), Error> {
    match crc_size {
        2 => out
            .extend_from_slice(&desfire_crc16(data))
            .map_err(|_| Error::CommandTooLong),
        4 => out
            .extend_from_slice(&desfire_crc32(data))
            .map_err(|_| Error::CommandTooLong),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn desfire_crc_matches(data: &[u8], expected: &[u8]) -> bool {
    match expected.len() {
        2 => desfire_crc16(data) == expected,
        4 => desfire_crc32(data) == expected,
        _ => false,
    }
}

fn has_valid_encrypted_response_padding(padding: &[u8]) -> bool {
    // DESFire EV1 emits method 2 (0x80 followed by zeros) when the payload length
    // is implicit (length=0 read) and method 1 (all zeros) when an exact length is
    // requested. Accept both so explicit-length encrypted reads validate.
    let Some((&first, rest)) = padding.split_first() else {
        return true;
    };

    (first == 0x80 || first == 0x00) && rest.iter().all(|&byte| byte == 0)
}

fn parse_application_ids<const N: usize>(
    data: &[u8],
    application_ids: &mut Vec<ApplicationId, N>,
) -> Result<(), Error> {
    if !data.len().is_multiple_of(3) {
        return Err(Error::InvalidResponseLength);
    }

    application_ids.clear();
    for chunk in data.chunks(3) {
        let bytes = chunk.try_into().expect("chunk size is checked");
        application_ids
            .push(ApplicationId::from_bytes(bytes))
            .map_err(|_| Error::ResponseTooLong)?;
    }

    Ok(())
}

fn parse_file_ids<const N: usize>(data: &[u8], file_ids: &mut Vec<FileId, N>) -> Result<(), Error> {
    file_ids.clear();
    for &id in data {
        file_ids
            .push(FileId::new(id)?)
            .map_err(|_| Error::ResponseTooLong)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use heapless::Vec;

    use crate::mifare::desfire::{
        application::ApplicationId,
        client::Desfire,
        crypto::{
            aes_cbc_encrypt_in_place, AesSessionKey, DesSessionKey, RndA, RndA8, RndB,
            ThreeKey3DesSessionKey, TwoKey3DesSessionKey,
        },
        error::Error,
        file::{AccessCondition, AccessRights, CommunicationMode, FileId, FileSettingsDetails},
        framing::{NativeFraming, WrappedFraming},
        key::{ApplicationKeyType, KeyNumber, KeySettings},
        session::{AuthenticatedSession, Session, SessionKey},
        transport::{Frame, Transport},
        types::U24,
    };

    struct MockTransport<const N: usize> {
        exchanges: [(&'static [u8], &'static [u8]); N],
        index: usize,
    }

    impl<const N: usize> MockTransport<N> {
        const fn new(exchanges: [(&'static [u8], &'static [u8]); N]) -> Self {
            Self {
                exchanges,
                index: 0,
            }
        }
    }

    impl<const N: usize> Transport for MockTransport<N> {
        fn transceive(&mut self, tx: &[u8], rx: &mut Frame) -> Result<(), Error> {
            let (expected_tx, response) = self.exchanges[self.index];
            self.index += 1;

            assert_eq!(tx, expected_tx);
            rx.clear();
            rx.extend_from_slice(response).map_err(|_| Error::Transport)
        }
    }

    #[cfg(feature = "std")]
    struct DynMockTransport {
        exchanges: std::vec::Vec<(std::vec::Vec<u8>, std::vec::Vec<u8>)>,
        index: usize,
    }

    #[cfg(feature = "std")]
    impl DynMockTransport {
        fn new(exchanges: std::vec::Vec<(std::vec::Vec<u8>, std::vec::Vec<u8>)>) -> Self {
            Self {
                exchanges,
                index: 0,
            }
        }
    }

    #[cfg(feature = "std")]
    impl Transport for DynMockTransport {
        fn transceive(&mut self, tx: &[u8], rx: &mut Frame) -> Result<(), Error> {
            let (expected_tx, response) = &self.exchanges[self.index];
            self.index += 1;
            assert_eq!(tx, expected_tx.as_slice());
            rx.clear();
            rx.extend_from_slice(response).map_err(|_| Error::Transport)
        }
    }

    struct OwnedMockTransport<const N: usize, const M: usize> {
        exchanges: [([u8; M], usize, [u8; M], usize); N],
        index: usize,
    }

    impl<const N: usize, const M: usize> OwnedMockTransport<N, M> {
        const fn new(exchanges: [([u8; M], usize, [u8; M], usize); N]) -> Self {
            Self {
                exchanges,
                index: 0,
            }
        }
    }

    impl<const N: usize, const M: usize> Transport for OwnedMockTransport<N, M> {
        fn transceive(&mut self, tx: &[u8], rx: &mut Frame) -> Result<(), Error> {
            let (expected_tx, expected_tx_len, response, response_len) = self.exchanges[self.index];
            self.index += 1;

            assert_eq!(tx, &expected_tx[..expected_tx_len]);
            rx.clear();
            rx.extend_from_slice(&response[..response_len])
                .map_err(|_| Error::Transport)
        }
    }

    #[test]
    fn selects_application() {
        let transport = MockTransport::new([(&[0x5A, 0x56, 0x34, 0x12][..], &[0x00][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x12_34_56).unwrap())
            .unwrap();

        assert_eq!(desfire.executor().transport().index, 1);
    }

    #[test]
    fn reads_application_ids() {
        let transport =
            MockTransport::new([(&[0x6A][..], &[0x00, 0x03, 0x02, 0x01, 0x06, 0x05, 0x04][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);
        let mut application_ids: Vec<crate::mifare::desfire::ApplicationId, 4> = Vec::new();

        desfire.get_application_ids(&mut application_ids).unwrap();

        assert_eq!(application_ids.len(), 2);
        assert_eq!(application_ids[0].as_u32(), 0x01_02_03);
        assert_eq!(application_ids[1].as_u32(), 0x04_05_06);
    }

    #[test]
    fn reads_file_ids() {
        let transport = MockTransport::new([(&[0x6F][..], &[0x00, 0x01, 0x02, 0x03][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);
        let mut file_ids: Vec<FileId, 4> = Vec::new();

        desfire.get_file_ids(&mut file_ids).unwrap();

        assert_eq!(
            file_ids.as_slice(),
            &[
                FileId::new(0x01).unwrap(),
                FileId::new(0x02).unwrap(),
                FileId::new(0x03).unwrap()
            ]
        );
    }

    #[test]
    fn reads_key_settings() {
        let transport = MockTransport::new([(&[0x45][..], &[0x00, 0x0F, 0x82][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let settings = desfire.get_key_settings().unwrap();

        assert_eq!(settings.key_count(), 2);
        assert_eq!(settings.key_type(), ApplicationKeyType::Aes);
    }

    #[test]
    fn reads_key_version() {
        let transport = MockTransport::new([(&[0x64, 0x01][..], &[0x00, 0x42][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let version = desfire.get_key_version(KeyNumber::new(1).unwrap()).unwrap();

        assert_eq!(version, 0x42);
    }

    #[test]
    fn authenticates_with_aes() {
        let key = [0x11; 16];
        let rnd_a = RndA::new([
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ]);
        let rnd_b = RndB::new([
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
            0xBE, 0xBF,
        ]);

        let mut encrypted_rnd_b = rnd_b.as_bytes();
        aes_cbc_encrypt_in_place(&key, &[0u8; 16], &mut encrypted_rnd_b);

        let mut encrypted_challenge = [0u8; 32];
        encrypted_challenge[..16].copy_from_slice(&rnd_a.as_bytes());
        encrypted_challenge[16..].copy_from_slice(&rnd_b.rotate_left());
        aes_cbc_encrypt_in_place(&key, &encrypted_rnd_b, &mut encrypted_challenge);

        let mut encrypted_rotated_rnd_a = rnd_a.rotate_left();
        let response_iv: [u8; 16] = encrypted_challenge[16..32].try_into().unwrap();
        aes_cbc_encrypt_in_place(&key, &response_iv, &mut encrypted_rotated_rnd_a);

        let mut first_response = [0u8; 17];
        first_response[0] = 0xAF;
        first_response[1..].copy_from_slice(&encrypted_rnd_b);
        let mut second_response = [0u8; 17];
        second_response[0] = 0x00;
        second_response[1..].copy_from_slice(&encrypted_rotated_rnd_a);

        let mut second_command = [0u8; 33];
        second_command[0] = 0xAF;
        second_command[1..].copy_from_slice(&encrypted_challenge);

        let mut first_command = [0u8; 33];
        first_command[..2].copy_from_slice(&[0xAA, 0x01]);
        let mut first_response_padded = [0u8; 33];
        first_response_padded[..17].copy_from_slice(&first_response);
        let mut second_response_padded = [0u8; 33];
        second_response_padded[..17].copy_from_slice(&second_response);
        let mut select_command = [0u8; 33];
        select_command[..4].copy_from_slice(&[0x5A, 0x56, 0x34, 0x12]);
        let mut select_response = [0u8; 33];
        select_response[0] = 0x00;

        let transport = OwnedMockTransport::new([
            (first_command, 2, first_response_padded, 17),
            (second_command, 33, second_response_padded, 17),
            (select_command, 4, select_response, 1),
        ]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let session = desfire
            .authenticate_aes_with_rnd_a(KeyNumber::new(1).unwrap(), &key, rnd_a)
            .unwrap();

        assert_eq!(session.key_number(), KeyNumber::new(1).unwrap());
        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::derive(rnd_a, rnd_b))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.authenticated_session(), Some(session));

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x12_34_56).unwrap())
            .unwrap();

        assert_eq!(desfire.session(), Session::Unauthenticated);
        assert_eq!(desfire.authenticated_session(), None);
    }

    #[test]
    fn authenticates_with_des_from_native_trace() {
        let key = [0u8; 8];
        let rnd_a = RndA8::new([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]);

        let transport = MockTransport::new([
            (
                &[0x0A, 0x00][..],
                &[0xAF, 0x74, 0xF4, 0xAE, 0x77, 0x7A, 0xA4, 0x31, 0xE8][..],
            ),
            (
                &[
                    0xAF, 0x02, 0x46, 0xEC, 0xD6, 0xA6, 0x6B, 0x0C, 0x06, 0xFC, 0xEE, 0x17, 0x72,
                    0x59, 0x76, 0xA7, 0xA4,
                ][..],
                &[0x00, 0x00, 0x41, 0x14, 0xFC, 0xBC, 0x1F, 0x0C, 0x48][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let session = desfire
            .authenticate_des_with_rnd_a(KeyNumber::new(0).unwrap(), &key, rnd_a)
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Des(DesSessionKey::new([
                0xA0, 0xA1, 0xA2, 0xA3, 0x00, 0x11, 0x22, 0x33
            ]))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.executor().transport().index, 2);
    }

    #[test]
    fn authenticates_with_2tdea_from_native_trace() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let rnd_a = RndA8::new([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]);

        let transport = MockTransport::new([
            (
                &[0x1A, 0x01][..],
                &[0xAF, 0xD1, 0x17, 0xBD, 0x63, 0x73, 0x54, 0x9F, 0xAA][..],
            ),
            (
                &[
                    0xAF, 0x88, 0x6E, 0xDC, 0xAE, 0x3F, 0xBC, 0x7F, 0xB2, 0x03, 0x98, 0x9F, 0xF0,
                    0x7E, 0xCD, 0x71, 0x77,
                ][..],
                &[0x00, 0x47, 0xBF, 0xAA, 0x80, 0xFF, 0x4F, 0xD3, 0xE8][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let session = desfire
            .authenticate_2tdea_with_rnd_a(KeyNumber::new(1).unwrap(), &key, rnd_a)
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0xA0, 0xA1, 0xA2, 0xA3, 0x00, 0x11, 0x22, 0x33, 0xA4, 0xA5, 0xA6, 0xA7, 0x44, 0x55,
                0x66, 0x77
            ]))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.executor().transport().index, 2);
    }

    #[test]
    fn authenticates_with_wrapped_2tdea_picc_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0x0C, 0x96, 0x9F, 0x9B, 0xC6, 0xA8, 0x3B, 0x1D, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0xD2, 0xB4, 0x94, 0x64, 0xD4, 0x0B, 0x94, 0x81,
                    0xF0, 0x08, 0x09, 0xEB, 0x2C, 0x4E, 0x16, 0x6E, 0x00,
                ][..],
                &[0xA7, 0x17, 0x3B, 0xA9, 0x34, 0x4C, 0x93, 0xE2, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();

        assert_eq!(session.key_number(), KeyNumber::new(0).unwrap());
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xD6, 0x5D, 0x6A, 0xE3, 0x05, 0x06, 0x07, 0x08, 0xE2, 0x83,
                0xAC, 0xC4
            ]))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.executor().transport().index, 2);
    }

    #[test]
    fn authenticates_with_wrapped_2tdea_app_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x22, 0x22, 0x22, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0x4C, 0xE0, 0x5C, 0x47, 0x6B, 0x59, 0xA1, 0xB4, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0x3B, 0xB5, 0xB4, 0xCB, 0x54, 0xC8, 0x06, 0xAC,
                    0x32, 0x2B, 0x0A, 0x22, 0x3A, 0x60, 0x10, 0x4A, 0x00,
                ][..],
                &[0xAB, 0x0F, 0x7D, 0x0D, 0x13, 0xBF, 0x50, 0x0F, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x22_22_22).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();

        assert_eq!(session.key_number(), KeyNumber::new(0).unwrap());
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x3E, 0x66, 0x1F, 0x9F, 0x05, 0x06, 0x07, 0x08, 0x2D, 0x49,
                0xAC, 0x4D
            ]))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.executor().transport().index, 3);
    }

    #[test]
    fn gets_key_settings_after_wrapped_2tdea_auth_proxmark_trace() {
        // Proxmark3 trace: hf mfdes getkeysettings --aid 123456 -t 2tdea --schann ev1
        // Proxmark reports the EV1 secure messaging key: 01 02 03 04 C1 BF 6D 84 repeated.
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x56, 0x34, 0x12, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0x8E, 0xC6, 0xE4, 0x1E, 0xE5, 0x2F, 0x08, 0x86, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0x88, 0x08, 0x6B, 0xEC, 0x47, 0x7E, 0xBE, 0x5E,
                    0x61, 0x09, 0x59, 0xA4, 0xBA, 0xF9, 0x29, 0xC7, 0x00,
                ][..],
                &[0xE8, 0x59, 0xD0, 0x11, 0xF6, 0xEF, 0x11, 0x6E, 0x91, 0x00][..],
            ),
            (
                &[0x90, 0x45, 0x00, 0x00, 0x00][..],
                &[
                    0x0F, 0x0E, 0xFB, 0xC9, 0x66, 0x2A, 0xD4, 0x90, 0xAD, 0x86, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x12_34_56).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xC1, 0xBF, 0x6D, 0x84, 0x05, 0x06, 0x07, 0x08, 0xDD, 0xFD,
                0xD2, 0xC7
            ]))
        );

        let settings = desfire.get_key_settings().unwrap();

        assert_eq!(settings.raw_settings(), 0x0F);
        assert_eq!(settings.raw_key_count(), 0x0E);
        assert_eq!(settings.key_count(), 14);
        assert_eq!(settings.key_type(), ApplicationKeyType::TwoKey3Des);
        assert_eq!(desfire.executor().transport().index, 4);
    }

    #[test]
    fn gets_key_settings_after_wrapped_3tdea_auth_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x33, 0x33, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0xE9, 0x22, 0x16, 0x2B, 0xAE, 0xB9, 0x36, 0x3E, 0x70, 0xCC, 0x92, 0x93, 0xBC,
                    0x4E, 0x17, 0x86, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0xBF, 0x0D, 0x53, 0xD9, 0x6B, 0x8E, 0x5E, 0x09,
                    0xFB, 0x5A, 0x52, 0xCC, 0xC5, 0x15, 0x6B, 0x22, 0x55, 0xC4, 0x9A, 0x73, 0xBD,
                    0xC0, 0xBC, 0x02, 0xD4, 0xED, 0x6A, 0xC4, 0xDC, 0x85, 0x1E, 0xAE, 0x00,
                ][..],
                &[
                    0x3C, 0x04, 0x88, 0xE8, 0xC2, 0x8C, 0x96, 0x85, 0xE7, 0x4E, 0xF9, 0x94, 0x20,
                    0xF3, 0x39, 0xA5, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0x45, 0x00, 0x00, 0x00][..],
                &[
                    0x0F, 0x4E, 0x83, 0x1B, 0x4A, 0xB1, 0x9F, 0x5F, 0xD0, 0xA7, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x33_33_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_3tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 24],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::ThreeKey3Des(ThreeKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xE0, 0xB8, 0xA0, 0xA5, 0x07, 0x08, 0x09, 0x10, 0xD5, 0xD0,
                0x06, 0x12, 0x13, 0x14, 0x15, 0x16, 0x36, 0x68, 0x59, 0x96
            ]))
        );

        let settings = desfire.get_key_settings().unwrap();

        assert_eq!(settings.raw_settings(), 0x0F);
        assert_eq!(settings.raw_key_count(), 0x4E);
        assert_eq!(settings.key_count(), 14);
        assert_eq!(settings.key_type(), ApplicationKeyType::ThreeKey3Des);
        assert_eq!(desfire.executor().transport().index, 4);
    }

    #[test]
    fn reads_plain_data_maced_after_wrapped_2tdea_auth_proxmark_trace() {
        // Proxmark3 trace: hf mfdes read --aid 123456 --fid 01 -t 2tdea --schann ev1
        // Proxmark reports the EV1 secure messaging key: 01 02 03 04 B6 BB 4E D5 repeated.
        // File 01: Standard, Plain comm mode, size 16, data = [0u8; 16]
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x56, 0x34, 0x12, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0xE2, 0x66, 0xC6, 0x43, 0x85, 0x40, 0xAF, 0xAD, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0x73, 0x16, 0x61, 0x92, 0xF5, 0x27, 0x7C, 0x42,
                    0xCB, 0x15, 0x9C, 0x84, 0xE0, 0x0A, 0x48, 0x70, 0x00,
                ][..],
                &[0x5D, 0x8B, 0x92, 0x22, 0x6C, 0xCE, 0xC3, 0x2E, 0x91, 0x00][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x00, 0xEE, 0xEE, 0x10, 0x00, 0x00, 0x0E, 0x3E, 0x0A, 0x32, 0xDA, 0xE7,
                    0x00, 0xD6, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0xE0, 0x35, 0x19, 0x27, 0xF9, 0xAB, 0x1C, 0x59, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x12_34_56).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xB6, 0xBB, 0x4E, 0xD5, 0x05, 0x06, 0x07, 0x08, 0x97, 0xE6,
                0x21, 0xC8
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Plain);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_maced(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(data.as_slice(), &[0u8; 16]);
        assert_eq!(desfire.executor().transport().index, 5);
    }

    #[test]
    fn reads_enciphered_data_after_wrapped_3tdea_auth_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x33, 0x33, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x8F, 0x63, 0x57, 0xB8, 0xEA, 0xBA, 0x01, 0x54, 0x72, 0x70, 0xD7, 0x9F, 0x5C,
                    0xAF, 0xA8, 0x4B, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0xFA, 0xAD, 0xD2, 0xB9, 0x05, 0x6E, 0x14, 0x48,
                    0xC8, 0x77, 0x69, 0xFA, 0x05, 0x7D, 0xF0, 0xA7, 0x3B, 0x32, 0xD9, 0x10, 0x06,
                    0xBF, 0xDE, 0x81, 0xD5, 0xBD, 0x38, 0x0D, 0xE6, 0xCE, 0xED, 0x9E, 0x00,
                ][..],
                &[
                    0xE5, 0x62, 0xB9, 0x35, 0x7B, 0xE7, 0x78, 0xCC, 0x86, 0x8C, 0xB9, 0x59, 0x19,
                    0xC0, 0x83, 0xD0, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0xD3, 0x41, 0x2F, 0xAE, 0xAB, 0x6A,
                    0x3E, 0x11, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0xC0, 0x84, 0x2F, 0x5E, 0x72, 0x2E, 0x82, 0x3B, 0xF7, 0x58, 0xC5, 0x80, 0xA4,
                    0xDC, 0xEC, 0x62, 0x38, 0x08, 0x01, 0xAB, 0x79, 0x8F, 0xA2, 0x16, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x33_33_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_3tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 24],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::ThreeKey3Des(ThreeKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xD4, 0x6B, 0x8F, 0xB1, 0x07, 0x08, 0x09, 0x10, 0x40, 0x82,
                0x4C, 0xED, 0x13, 0x14, 0x15, 0x16, 0x1C, 0x69, 0x90, 0x16
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_enciphered(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(data.as_slice(), &[0u8; 16]);
        assert_eq!(desfire.executor().transport().index, 5);
    }

    #[test]
    fn rejects_2tdea_create_application_response_mac_mismatch_proxmark_trace() {
        // Proxmark3 trace (PICC auth): hf mfdes getkeysettings -t 2tdea --schann ev1
        // Proxmark reports the EV1 secure messaging key: 01 02 03 04 35 FF 66 57 repeated.
        // CreateApp response replaced with all-zero MAC to trigger InvalidMac rejection.
        let transport = MockTransport::new([
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0x9F, 0xA7, 0xBD, 0x1F, 0xE7, 0x8F, 0x50, 0x92, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0xAF, 0x64, 0x6D, 0x0C, 0x60, 0x80, 0xF1, 0x58,
                    0x57, 0x91, 0xBB, 0xBC, 0x33, 0x6B, 0x04, 0x9C, 0x00,
                ][..],
                &[0xDE, 0x69, 0xD6, 0x7F, 0x5A, 0xC2, 0x1C, 0x48, 0x91, 0x00][..],
            ),
            (
                &[
                    0x90, 0xCA, 0x00, 0x00, 0x05, 0x44, 0x44, 0x44, 0x0F, 0x0E, 0x00,
                ][..],
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x35, 0xFF, 0x66, 0x57, 0x05, 0x06, 0x07, 0x08, 0x40, 0x5E,
                0x2C, 0x9A
            ]))
        );

        let error = desfire
            .create_application(
                ApplicationId::new(0x44_44_44).unwrap(),
                KeySettings::new(0x0F, ApplicationKeyType::TwoKey3Des, 14),
            )
            .unwrap_err();

        assert_eq!(error, Error::InvalidMac);
        assert_eq!(desfire.executor().transport().index, 3);
    }

    #[test]
    fn creates_2tdea_application_after_wrapped_2tdea_picc_auth_proxmark_trace() {
        // Proxmark3 trace: hf mfdes createapp --aid 444444 -t 2tdea --schann ev1
        // Proxmark reports the EV1 secure messaging key: 01 02 03 04 26 E5 87 06 repeated.
        let transport = MockTransport::new([
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[0xD6, 0x0A, 0x7C, 0x54, 0x9B, 0xFC, 0xDC, 0xA8, 0x91, 0xAF][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x10, 0xD9, 0x66, 0xA5, 0xEF, 0x41, 0x6A, 0x56, 0x2D,
                    0xAF, 0xEF, 0x09, 0x74, 0x3B, 0x2E, 0x4E, 0xFB, 0x00,
                ][..],
                &[0xEB, 0xF3, 0xA5, 0xAF, 0x01, 0x21, 0x09, 0x5D, 0x91, 0x00][..],
            ),
            (
                &[
                    0x90, 0xCA, 0x00, 0x00, 0x05, 0x44, 0x44, 0x44, 0x0F, 0x0E, 0x00,
                ][..],
                &[0x26, 0x42, 0x0F, 0xA4, 0x63, 0xBC, 0xB2, 0xA2, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        let session = desfire
            .authenticate_2tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA8::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::TwoKey3Des(TwoKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x26, 0xE5, 0x87, 0x06, 0x05, 0x06, 0x07, 0x08, 0xF4, 0xA3,
                0xD8, 0x03
            ]))
        );

        desfire
            .create_application(
                ApplicationId::new(0x44_44_44).unwrap(),
                KeySettings::new(0x0F, ApplicationKeyType::TwoKey3Des, 14),
            )
            .unwrap();

        assert_eq!(desfire.executor().transport().index, 3);
    }

    #[test]
    fn creates_3tdea_application_after_wrapped_3tdea_picc_auth_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0xC6, 0x8E, 0xC2, 0x29, 0x5D, 0xD9, 0x1B, 0xD0, 0x5B, 0x1D, 0xCE, 0xA8, 0x34,
                    0x79, 0x61, 0x15, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0xF0, 0x11, 0x33, 0xAB, 0x46, 0x2D, 0xFF, 0xD2,
                    0x0F, 0xD1, 0xFD, 0x71, 0xAB, 0x52, 0xE6, 0x2C, 0x3E, 0xA4, 0x71, 0x5B, 0x22,
                    0xEC, 0x10, 0x8E, 0x5B, 0x54, 0xB7, 0x4F, 0xA8, 0x2D, 0xCF, 0xF6, 0x00,
                ][..],
                &[
                    0x4C, 0x95, 0x25, 0x20, 0xC5, 0x6A, 0x10, 0xF4, 0x3C, 0x4B, 0xC9, 0x2E, 0x88,
                    0x97, 0x6A, 0x96, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xCA, 0x00, 0x00, 0x05, 0x55, 0x55, 0x55, 0x0F, 0x4E, 0x00,
                ][..],
                &[0x75, 0xDF, 0xAA, 0xA4, 0x8E, 0xCA, 0x79, 0x2A, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        let session = desfire
            .authenticate_3tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 24],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();
        assert_eq!(
            session.session_key(),
            SessionKey::ThreeKey3Des(ThreeKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xE3, 0x63, 0x90, 0x66, 0x07, 0x08, 0x09, 0x10, 0xD2, 0xE8,
                0x98, 0xDE, 0x13, 0x14, 0x15, 0x16, 0x49, 0xD8, 0xC0, 0x2A
            ]))
        );

        desfire
            .create_application(
                ApplicationId::new(0x55_55_55).unwrap(),
                KeySettings::new(0x0F, ApplicationKeyType::ThreeKey3Des, 14),
            )
            .unwrap();

        assert_eq!(desfire.executor().transport().index, 3);
    }

    #[test]
    fn authenticates_with_wrapped_3tdea_app_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x33, 0x33, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x61, 0x26, 0x6B, 0xDB, 0xDA, 0xDF, 0xE7, 0xCD, 0xD4, 0xFE, 0xE3, 0x23, 0x9A,
                    0xE8, 0x26, 0x9F, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x37, 0x5F, 0x72, 0x86, 0xC3, 0x81, 0xD6, 0x94,
                    0x6B, 0x6F, 0x4C, 0x80, 0x14, 0x79, 0x75, 0xBE, 0x6C, 0xAD, 0x9B, 0x2B, 0x10,
                    0x3A, 0xDF, 0x31, 0x15, 0xA3, 0x6B, 0xB3, 0x07, 0xD1, 0x3E, 0x3F, 0x00,
                ][..],
                &[
                    0x1F, 0x19, 0xDE, 0x9A, 0x33, 0x33, 0x5C, 0xD4, 0x47, 0x25, 0xBA, 0x57, 0x33,
                    0xCA, 0xB9, 0x4F, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x33_33_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_3tdea_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 24],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(session.key_number(), KeyNumber::new(0).unwrap());
        assert_eq!(
            session.session_key(),
            SessionKey::ThreeKey3Des(ThreeKey3DesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xC0, 0x06, 0x38, 0x44, 0x07, 0x08, 0x09, 0x10, 0x1D, 0x00,
                0x99, 0xFA, 0x13, 0x14, 0x15, 0x16, 0x62, 0x2F, 0x4A, 0x01
            ]))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
        assert_eq!(desfire.executor().transport().index, 3);
    }

    #[test]
    fn authenticates_with_wrapped_aes_proxmark_traces() {
        assert_wrapped_aes_auth_trace(
            &[
                0x17, 0x34, 0x80, 0x9D, 0xCA, 0x92, 0x93, 0xFC, 0x5B, 0xAF, 0x4A, 0x9A, 0x0D, 0x5C,
                0x56, 0x2D, 0x91, 0xAF,
            ],
            &[
                0x90, 0xAF, 0x00, 0x00, 0x20, 0xB0, 0x1B, 0x55, 0x74, 0x08, 0x4A, 0x37, 0x14, 0x92,
                0x52, 0xE9, 0xCA, 0x4A, 0x44, 0x80, 0x74, 0x42, 0x21, 0x81, 0xCF, 0x67, 0xC0, 0x9D,
                0xE5, 0x06, 0x3B, 0x37, 0xC2, 0xF0, 0xCD, 0xF5, 0x8A, 0x00,
            ],
            &[
                0xA6, 0xF8, 0x91, 0x88, 0xE2, 0x9C, 0x82, 0x22, 0xF6, 0xD9, 0x87, 0x42, 0x70, 0x55,
                0xA1, 0x26, 0x91, 0x00,
            ],
            [
                0x01, 0x02, 0x03, 0x04, 0x47, 0xDB, 0x4F, 0x91, 0x13, 0x14, 0x15, 0x16, 0x6E, 0xC6,
                0x58, 0x25,
            ],
        );

        assert_wrapped_aes_auth_trace(
            &[
                0x6C, 0xE8, 0x11, 0xA3, 0x7F, 0x10, 0x8E, 0x9F, 0xDB, 0x58, 0x54, 0xF9, 0x11, 0xA5,
                0x2E, 0xDD, 0x91, 0xAF,
            ],
            &[
                0x90, 0xAF, 0x00, 0x00, 0x20, 0x72, 0x0C, 0x78, 0xDB, 0x3B, 0x89, 0xF8, 0x19, 0x1F,
                0x2B, 0xC0, 0xAC, 0x23, 0x99, 0x38, 0xBE, 0xC5, 0xB2, 0xE5, 0xAE, 0x8B, 0xE6, 0x49,
                0x24, 0x8A, 0x28, 0xF7, 0x02, 0xB0, 0xFA, 0x54, 0x60, 0x00,
            ],
            &[
                0x70, 0x07, 0x16, 0xB7, 0xF3, 0x5E, 0xE7, 0x9B, 0xBF, 0xF5, 0x22, 0xF0, 0xE3, 0xC0,
                0x90, 0xCC, 0x91, 0x00,
            ],
            [
                0x01, 0x02, 0x03, 0x04, 0xE5, 0xFF, 0xED, 0x4F, 0x13, 0x14, 0x15, 0x16, 0xC6, 0x74,
                0xAA, 0x8E,
            ],
        );

        assert_wrapped_aes_auth_trace(
            &[
                0x22, 0x0B, 0xE6, 0x13, 0xA2, 0x81, 0xA7, 0x65, 0xBC, 0x29, 0xE2, 0xFC, 0xFF, 0x95,
                0x4D, 0x35, 0x91, 0xAF,
            ],
            &[
                0x90, 0xAF, 0x00, 0x00, 0x20, 0x2C, 0x90, 0x62, 0x31, 0x21, 0x3F, 0x7F, 0x19, 0xBC,
                0x63, 0xBA, 0x7D, 0x06, 0xA1, 0x5D, 0x6D, 0x48, 0x0D, 0xAA, 0x94, 0x78, 0xAD, 0xC6,
                0x35, 0xC2, 0xF9, 0x74, 0x52, 0x9B, 0x6C, 0xD9, 0x9D, 0x00,
            ],
            &[
                0x3C, 0x08, 0x02, 0xF3, 0xD8, 0xCC, 0xC8, 0xA2, 0x54, 0x82, 0x12, 0x85, 0xA7, 0x59,
                0x22, 0xDC, 0x91, 0x00,
            ],
            [
                0x01, 0x02, 0x03, 0x04, 0xB0, 0x39, 0x10, 0xE5, 0x13, 0x14, 0x15, 0x16, 0x7F, 0x00,
                0x6F, 0x45,
            ],
        );
    }

    fn assert_wrapped_aes_auth_trace(
        first_response: &'static [u8],
        second_command: &'static [u8],
        second_response: &'static [u8],
        expected_session_key: [u8; 16],
    ) {
        let transport = MockTransport::new([
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                first_response,
            ),
            (second_command, second_response),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(session.key_number(), KeyNumber::new(0).unwrap());
        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new(expected_session_key))
        );
        assert_eq!(desfire.session(), Session::Authenticated(session));
    }

    #[test]
    fn reads_enciphered_data_from_wrapped_proxmark_trace() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x22, 0x11, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x96, 0x4A, 0x05, 0x8E, 0x52, 0xA2, 0xB3, 0x15, 0x72, 0x89, 0x39, 0x34, 0x90,
                    0x27, 0x93, 0x68, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x05, 0x7A, 0x57, 0x88, 0x36, 0xC1, 0x5C, 0x8F,
                    0x9E, 0x69, 0x1B, 0xE2, 0x7C, 0xCC, 0x6F, 0x70, 0x7F, 0xBF, 0x6D, 0x36, 0x1F,
                    0xC0, 0x6D, 0x5E, 0x69, 0x20, 0x3C, 0x87, 0xE9, 0x7B, 0x44, 0x55, 0x00,
                ][..],
                &[
                    0x70, 0xA4, 0x01, 0xC7, 0x5A, 0xF6, 0xF8, 0xDB, 0xE8, 0x65, 0x2C, 0x1C, 0x50,
                    0x0D, 0xCE, 0xAF, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x2C, 0x90, 0x88, 0x7A, 0x35, 0x22,
                    0xDE, 0xC3, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x8E, 0x2D, 0x96, 0x48, 0x75, 0xDC, 0x9E, 0xC2, 0x55, 0x32, 0x93, 0xEF, 0x12,
                    0x37, 0x3A, 0x05, 0x85, 0xB7, 0x64, 0x05, 0x12, 0xE9, 0x55, 0xAE, 0xFB, 0xC0,
                    0x20, 0x76, 0x9E, 0xA4, 0xCC, 0xC7, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x11_22_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xEB, 0x8D, 0x9B, 0xE8, 0x13, 0x14, 0x15, 0x16, 0xBE, 0xBB,
                0x9B, 0x4A,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_enciphered(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(
            data.as_slice(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            ]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn reads_maced_data() {
        // Auth from EV2 proxmark trace (key=00..00), session key 01 02 03 04 7C B5 EA 83 ...
        // After auth, chaining state resets to [0x00;16], so MAC is deterministic from SK.
        use crate::mifare::desfire::crypto::{AesCmacChaining, AesSessionKey};

        let sk = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x7C, 0xB5, 0xEA, 0x83, 0x13, 0x14, 0x15, 0x16, 0xD8, 0x51,
            0xEF, 0x57,
        ]);
        let body = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        // Compute expected MAC: mirrors what read_data_maced will compute internally.
        let mut chaining = AesCmacChaining::new();
        chaining.update(sk, &[0xBD, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00]);
        let mut resp_input = [0u8; 9];
        resp_input[..8].copy_from_slice(&body);
        // resp_input[8] = 0x00 = Status::OperationOk
        let mac = chaining.update(sk, &resp_input).desfire_mac();

        // Build mock read response: body + MAC + 91 00 (wrapped OperationOk)
        let mut read_response = std::vec::Vec::new();
        read_response.extend_from_slice(&body);
        read_response.extend_from_slice(&mac.as_bytes());
        read_response.extend_from_slice(&[0x91, 0x00]);

        let transport = DynMockTransport::new(std::vec![
            // select application 112233
            (
                std::vec![0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x22, 0x11, 0x00],
                std::vec![0x91, 0x00],
            ),
            // auth first (AA)
            (
                std::vec![0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00],
                std::vec![
                    0x2C, 0x97, 0x4F, 0x0E, 0xA0, 0x0C, 0xFD, 0x73, 0x67, 0x1E, 0x6A, 0x97, 0xAE,
                    0x13, 0x89, 0x91, 0x91, 0xAF,
                ],
            ),
            // auth second (AF)
            (
                std::vec![
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x2C, 0xAB, 0xDF, 0x18, 0xCF, 0x46, 0x0C, 0xE5,
                    0xA8, 0x7A, 0xDD, 0x3B, 0xA8, 0xA0, 0x44, 0xD3, 0x50, 0x2A, 0x6E, 0x5F, 0xF5,
                    0xA4, 0xF6, 0x19, 0xF6, 0xBD, 0xBF, 0x90, 0x2A, 0x09, 0xB5, 0x41, 0x00,
                ],
                std::vec![
                    0x0D, 0xCD, 0xFB, 0xE5, 0xE7, 0xDB, 0x22, 0x83, 0xF5, 0x81, 0xF6, 0x1D, 0x0D,
                    0xD9, 0x75, 0xEA, 0x91, 0x00,
                ],
            ),
            // read data maced: file=1 offset=0 length=8
            (
                std::vec![
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                ],
                read_response,
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x11_22_33).unwrap())
            .unwrap();
        desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();
        desfire
            .read_data_maced(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(8).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(
            data.as_slice(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn reads_maced_data_rejects_bad_mac() {
        use crate::mifare::desfire::crypto::{AesCmacChaining, AesSessionKey};

        let sk = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x7C, 0xB5, 0xEA, 0x83, 0x13, 0x14, 0x15, 0x16, 0xD8, 0x51,
            0xEF, 0x57,
        ]);
        let body = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let mut chaining = AesCmacChaining::new();
        chaining.update(sk, &[0xBD, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00]);
        let mut resp_input = [0u8; 9];
        resp_input[..8].copy_from_slice(&body);
        let mut mac = chaining.update(sk, &resp_input).desfire_mac().as_bytes();
        mac[0] ^= 0xFF; // corrupt MAC

        let mut read_response = std::vec::Vec::new();
        read_response.extend_from_slice(&body);
        read_response.extend_from_slice(&mac);
        read_response.extend_from_slice(&[0x91, 0x00]);

        let transport = DynMockTransport::new(std::vec![
            (
                std::vec![0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x22, 0x11, 0x00],
                std::vec![0x91, 0x00],
            ),
            (
                std::vec![0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00],
                std::vec![
                    0x2C, 0x97, 0x4F, 0x0E, 0xA0, 0x0C, 0xFD, 0x73, 0x67, 0x1E, 0x6A, 0x97, 0xAE,
                    0x13, 0x89, 0x91, 0x91, 0xAF,
                ],
            ),
            (
                std::vec![
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x2C, 0xAB, 0xDF, 0x18, 0xCF, 0x46, 0x0C, 0xE5,
                    0xA8, 0x7A, 0xDD, 0x3B, 0xA8, 0xA0, 0x44, 0xD3, 0x50, 0x2A, 0x6E, 0x5F, 0xF5,
                    0xA4, 0xF6, 0x19, 0xF6, 0xBD, 0xBF, 0x90, 0x2A, 0x09, 0xB5, 0x41, 0x00,
                ],
                std::vec![
                    0x0D, 0xCD, 0xFB, 0xE5, 0xE7, 0xDB, 0x22, 0x83, 0xF5, 0x81, 0xF6, 0x1D, 0x0D,
                    0xD9, 0x75, 0xEA, 0x91, 0x00,
                ],
            ),
            (
                std::vec![
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                ],
                read_response,
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x11_22_33).unwrap())
            .unwrap();
        desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        let err = desfire
            .read_data_maced(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(8).unwrap(),
                &mut data,
            )
            .unwrap_err();

        assert_eq!(err, Error::InvalidMac);
    }

    #[test]
    fn reads_maced_data_from_wrapped_proxmark_trace() {
        // Proxmark3 trace: hf mfdes read --aid 223344 --fid 02 --keyno 0 --algo aes
        //   --key 00..00 --cmode plain (comm mode mac)
        // Response: 16 body bytes + 8-byte MAC (ISO 9797-1 CMAC, first 8 bytes).
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x44, 0x33, 0x22, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x7A, 0x00, 0x3C, 0x07, 0x5D, 0x01, 0x4D, 0x3F, 0x64, 0xEE, 0xD4, 0x6F, 0x05,
                    0xF0, 0x92, 0xDE, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x21, 0x1B, 0xD6, 0xE6, 0x7C, 0x27, 0xFE, 0x0F,
                    0x04, 0xBA, 0xEA, 0x85, 0x97, 0xFE, 0x2E, 0x3B, 0x9D, 0x62, 0x3E, 0xE4, 0x8A,
                    0x82, 0x00, 0x68, 0x9E, 0xBE, 0xA7, 0xF2, 0x66, 0xB1, 0x56, 0x41, 0x00,
                ][..],
                &[
                    0xA7, 0xC7, 0x6A, 0x5A, 0xEF, 0x13, 0x6B, 0x9F, 0xD0, 0xF2, 0xCD, 0x3B, 0x32,
                    0x39, 0xE6, 0x09, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x02, 0x00][..],
                &[
                    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0xB9, 0x51, 0x8B, 0x36, 0x52, 0xCE,
                    0x1A, 0xAC, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                    0x0E, 0x0F, 0x00, 0xC4, 0x56, 0x07, 0x5E, 0x59, 0x4E, 0x3D, 0x05, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x22_33_44).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x22, 0x67, 0xAE, 0x21, 0x13, 0x14, 0x15, 0x16, 0x6C, 0xBF,
                0x49, 0x39,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x02).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Maced);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_maced(
                FileId::new(0x02).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(
            data.as_slice(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x00
            ]
        );
    }

    #[test]
    fn reads_enciphered_8_bytes_explicit_length_ev2_proxmark_trace() {
        // Proxmark3 trace: hf mfdes read --aid 112233 --fid 01 --keyno 0 --algo aes
        //   --key 00..00 --offset 000000 --length 000008
        // Card returns 1 AES block (8 data + 4 CRC + 4 zero bytes, ISO 9797-1 method 1).
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x22, 0x11, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x2C, 0x97, 0x4F, 0x0E, 0xA0, 0x0C, 0xFD, 0x73, 0x67, 0x1E, 0x6A, 0x97, 0xAE,
                    0x13, 0x89, 0x91, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x2C, 0xAB, 0xDF, 0x18, 0xCF, 0x46, 0x0C, 0xE5,
                    0xA8, 0x7A, 0xDD, 0x3B, 0xA8, 0xA0, 0x44, 0xD3, 0x50, 0x2A, 0x6E, 0x5F, 0xF5,
                    0xA4, 0xF6, 0x19, 0xF6, 0xBD, 0xBF, 0x90, 0x2A, 0x09, 0xB5, 0x41, 0x00,
                ][..],
                &[
                    0x0D, 0xCD, 0xFB, 0xE5, 0xE7, 0xDB, 0x22, 0x83, 0xF5, 0x81, 0xF6, 0x1D, 0x0D,
                    0xD9, 0x75, 0xEA, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x3E, 0xBA, 0x9D, 0x55, 0x27, 0xBF,
                    0x70, 0xDA, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x65, 0xA8, 0x0B, 0xE4, 0x58, 0x73, 0xE0, 0xB5, 0x0E, 0xD8, 0x9D, 0xE7, 0x3F,
                    0x25, 0x2F, 0xA5, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x11_22_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x7C, 0xB5, 0xEA, 0x83, 0x13, 0x14, 0x15, 0x16, 0xD8, 0x51,
                0xEF, 0x57,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_enciphered(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(8).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(
            data.as_slice(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    #[test]
    fn reads_enciphered_16_bytes_zero_length_ev2_proxmark_trace() {
        // Proxmark3 trace: hf mfdes read --aid 112233 --fid 01 --keyno 0 --algo aes
        //   --key 00..00 --offset 000000 --length 000000
        // Card returns 2 AES blocks (16 data + 4 CRC + 12 bytes 0x80+zeros, ISO 9797-1 method 2).
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x33, 0x22, 0x11, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0xFC, 0xA5, 0x5E, 0x23, 0xCB, 0x0B, 0x34, 0xA5, 0xA5, 0x51, 0xBF, 0xB5, 0x6A,
                    0x0B, 0xEE, 0xF5, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x2E, 0x93, 0xF9, 0x9E, 0x1E, 0xA3, 0xD8, 0x6D,
                    0xBB, 0x08, 0x21, 0x23, 0x37, 0x29, 0x31, 0xC8, 0x2C, 0xFA, 0x40, 0x92, 0x7A,
                    0x4A, 0x1B, 0x4B, 0x2A, 0x71, 0x10, 0x56, 0x9B, 0x49, 0x10, 0x08, 0x00,
                ][..],
                &[
                    0x44, 0xEA, 0xA0, 0x27, 0x37, 0xF9, 0x28, 0x67, 0x58, 0xE9, 0xFA, 0x95, 0x83,
                    0x69, 0x8F, 0xC7, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x1D, 0xB7, 0x17, 0xE8, 0xC5, 0x74,
                    0x85, 0x8D, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x0D, 0x43, 0xFB, 0x0A, 0x60, 0x76, 0xBF, 0x80, 0x27, 0xB1, 0x54, 0xC5, 0x30,
                    0x71, 0x5B, 0x66, 0x2B, 0x2A, 0x46, 0x31, 0x15, 0xF5, 0x17, 0x7E, 0x78, 0xAF,
                    0x1C, 0xE1, 0x95, 0x14, 0xEA, 0x25, 0x91, 0x00,
                ][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);
        let mut data: Vec<u8, 32> = Vec::new();

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x11_22_33).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xB0, 0xDB, 0x9B, 0x27, 0x13, 0x14, 0x15, 0x16, 0x99, 0xAC,
                0xD4, 0x7F,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);
        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(16).unwrap()
            }
        );

        desfire
            .read_data_enciphered(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(
            data.as_slice(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            ]
        );
    }

    #[test]
    fn writes_enciphered_data_from_proxmark_trace() {
        // Proxmark3 trace: hf mfdes write --aid 223344 --fid 01
        //   -d 112233445566778899AABBCCDDEEFF --keyno 0 --algo aes
        // Encrypted payload: data(15) || CRC32(data)(4) || 0x80 || zeros(12) = 32 bytes.
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x44, 0x33, 0x22, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0x41, 0x65, 0x2F, 0xC4, 0xE4, 0xB0, 0xDF, 0x1E, 0xF8, 0x1B, 0x62, 0xE9, 0xC9,
                    0x8C, 0xA5, 0xEC, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x1F, 0x90, 0xF8, 0x2E, 0xE3, 0x0F, 0xA2, 0x9C,
                    0x8C, 0x0D, 0x3D, 0xC1, 0xBD, 0x07, 0x18, 0x1B, 0x3F, 0xF3, 0x08, 0x29, 0x76,
                    0x49, 0xDF, 0x58, 0x62, 0x58, 0x70, 0x6A, 0x58, 0x3C, 0x5A, 0xBB, 0x00,
                ][..],
                &[
                    0x9A, 0xE7, 0x3B, 0xE1, 0x0D, 0xE7, 0xA3, 0xA1, 0xAA, 0x75, 0x13, 0xF1, 0xB6,
                    0x44, 0xA9, 0x84, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0xEC, 0xBB, 0x9D, 0x25, 0x12, 0x54,
                    0xEE, 0x65, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0x3D, 0x00, 0x00, 0x27, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0xCA,
                    0x5E, 0x29, 0x0C, 0x21, 0x2A, 0x67, 0x10, 0xE9, 0xD8, 0xD3, 0x41, 0xA7, 0x2B,
                    0x1B, 0xE2, 0x0A, 0x4A, 0xD7, 0xD8, 0x8F, 0xDE, 0xE4, 0x04, 0x42, 0x5E, 0x2D,
                    0xB2, 0x71, 0x0F, 0x6B, 0xF9, 0x00,
                ][..],
                &[0x91, 0x77, 0x50, 0xBD, 0xF0, 0x1D, 0x17, 0xB3, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x22_33_44).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0xF7, 0x0F, 0xA1, 0xE2, 0x13, 0x14, 0x15, 0x16, 0xEA, 0xC9,
                0x18, 0x7D,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Enciphered);

        desfire
            .write_data_enciphered(
                FileId::new(0x01).unwrap(),
                U24::new(0).unwrap(),
                &[
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                    0xEE, 0xFF,
                ],
            )
            .unwrap();
    }

    #[test]
    fn writes_maced_data_from_proxmark_trace() {
        // Proxmark3 trace: hf mfdes write --aid 223344 --fid 02
        //   -d 0102030405060708090A0B0C0D0E0F --keyno 0 --algo aes
        // Command MAC appended after plaintext data.
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x44, 0x33, 0x22, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0xAF, 0x5A, 0x9C, 0x1E, 0x11, 0xB9, 0x9F, 0x03, 0xC7, 0xC0, 0x2A, 0x8D, 0xEF,
                    0x3E, 0x81, 0xCD, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x81, 0xF3, 0xBE, 0xD3, 0xFD, 0x7A, 0x3D, 0x7F,
                    0xE5, 0x45, 0x55, 0xB6, 0xF0, 0x5E, 0x64, 0x6E, 0x4C, 0xF6, 0xD4, 0x83, 0x21,
                    0x02, 0x7D, 0xA7, 0x96, 0x74, 0x8F, 0x3C, 0x7D, 0xF0, 0xE8, 0x8C, 0x00,
                ][..],
                &[
                    0x84, 0xF7, 0x00, 0xC2, 0xBE, 0x5A, 0x1D, 0xAB, 0x62, 0x53, 0xE4, 0x31, 0x16,
                    0x79, 0xBE, 0x0E, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x02, 0x00][..],
                &[
                    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0xF4, 0xAD, 0xA4, 0xC3, 0xDB, 0x7D,
                    0x0E, 0xE9, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0x3D, 0x00, 0x00, 0x1E, 0x02, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x01,
                    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                    0x0F, 0xF1, 0xC3, 0x91, 0x50, 0x6C, 0xDB, 0x6A, 0x2D, 0x00,
                ][..],
                &[0xEB, 0xDD, 0xE8, 0x5C, 0x53, 0x7B, 0x59, 0xE7, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x22_33_44).unwrap())
            .unwrap();
        let session = desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        assert_eq!(
            session.session_key(),
            SessionKey::Aes(AesSessionKey::new([
                0x01, 0x02, 0x03, 0x04, 0x75, 0x5E, 0x6A, 0x14, 0x13, 0x14, 0x15, 0x16, 0x70, 0x4B,
                0xDB, 0xD1,
            ]))
        );

        let settings = desfire
            .get_file_settings(FileId::new(0x02).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Maced);

        desfire
            .write_data_maced(
                FileId::new(0x02).unwrap(),
                U24::new(0).unwrap(),
                &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                    0x0E, 0x0F,
                ],
            )
            .unwrap();
    }

    #[test]
    fn writes_plain_data_from_proxmark_trace() {
        // Proxmark3 trace: hf mfdes write --aid 223344 --fid 03
        //   -d F0E0D0C0B0A0908070605040302010 --keyno 0 --algo aes
        // Plain write: no command MAC, response MAC ignored.
        let transport = MockTransport::new([
            (
                &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x44, 0x33, 0x22, 0x00][..],
                &[0x91, 0x00][..],
            ),
            (
                &[0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00][..],
                &[
                    0xB4, 0x72, 0xDB, 0x0D, 0x5D, 0xC8, 0x5F, 0xD2, 0x40, 0x92, 0xE4, 0xEB, 0x21,
                    0xB3, 0xFF, 0xA2, 0x91, 0xAF,
                ][..],
            ),
            (
                &[
                    0x90, 0xAF, 0x00, 0x00, 0x20, 0x8F, 0x53, 0xA0, 0x8C, 0xC8, 0x42, 0xF1, 0x57,
                    0x6F, 0xD1, 0xCD, 0x7D, 0x5B, 0x8D, 0xE1, 0x57, 0x62, 0x32, 0x26, 0xAB, 0x45,
                    0x3E, 0x79, 0xAA, 0xD7, 0x3D, 0xDA, 0x0A, 0x2D, 0x4C, 0xD2, 0x2B, 0x00,
                ][..],
                &[
                    0xE5, 0x7A, 0x40, 0x6C, 0xED, 0x55, 0x3F, 0x75, 0x7A, 0xC8, 0x91, 0x5A, 0x23,
                    0x9F, 0xFE, 0x77, 0x91, 0x00,
                ][..],
            ),
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x03, 0x00][..],
                &[
                    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x46, 0xA3, 0xDD, 0x30, 0x03, 0x86,
                    0xA9, 0xD3, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0x3D, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0xF0,
                    0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20,
                    0x10, 0x00,
                ][..],
                &[0x15, 0x46, 0xB9, 0x94, 0x55, 0xDD, 0x31, 0x5A, 0x91, 0x00][..],
            ),
        ]);
        let mut desfire = Desfire::new(transport, WrappedFraming);

        desfire
            .select_application(crate::mifare::desfire::ApplicationId::new(0x22_33_44).unwrap())
            .unwrap();
        desfire
            .authenticate_aes_with_rnd_a(
                KeyNumber::new(0).unwrap(),
                &[0u8; 16],
                RndA::new([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16,
                ]),
            )
            .unwrap();

        let settings = desfire
            .get_file_settings(FileId::new(0x03).unwrap())
            .unwrap();
        assert_eq!(settings.communication_mode(), CommunicationMode::Plain);

        desfire
            .write_data(
                FileId::new(0x03).unwrap(),
                U24::new(0).unwrap(),
                &[
                    0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30,
                    0x20, 0x10,
                ],
            )
            .unwrap();
    }

    #[test]
    fn reads_free_memory() {
        let transport = MockTransport::new([(&[0x6E][..], &[0x00, 0x20, 0x03, 0x00][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let memory = desfire.free_memory().unwrap();

        assert_eq!(memory.as_u32(), 800);
    }

    #[test]
    fn reads_file_settings() {
        let transport = MockTransport::new([(
            &[0xF5, 0x01][..],
            &[0x00, 0x00, 0x00, 0xEE, 0xEE, 0x20, 0x00, 0x00][..],
        )]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let settings = desfire
            .get_file_settings(FileId::new(0x01).unwrap())
            .unwrap();

        assert_eq!(
            settings.details(),
            FileSettingsDetails::Data {
                size: U24::new(32).unwrap()
            }
        );
    }

    #[test]
    fn reads_plain_data() {
        let transport = MockTransport::new([(
            &[0xBD, 0x01, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00][..],
            &[0x00, 0xDE, 0xAD, 0xBE, 0xEF][..],
        )]);
        let mut desfire = Desfire::new(transport, NativeFraming);
        let mut data: Vec<u8, 4> = Vec::new();

        desfire
            .read_data(
                FileId::new(0x01).unwrap(),
                U24::new(2).unwrap(),
                U24::new(4).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(data.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // Proxmark trace: `hf mfdes createapp --aid 222222 --no-auth --dstalgo aes --numkeys 1`
    // TX: 90 CA 00 00 05 22 22 22 0F 81 00  (wrapped; native: CA 22 22 22 0F 81)
    // RX: 91 00  (wrapped; native: 00)  — no MAC when unauthenticated
    #[test]
    fn change_file_settings_2tdea_proxmark_trace() {
        // Proxmark3 trace: hf mfdes chfilesettings --aid 222222 --fid 01
        //   --rrights key1 --wrights key1 --rwrights key1 --chrights key0 -n 0 -t 2tdea
        // Session key: 01 02 03 04 51 99 63 96 01 02 03 04 51 99 63 96
        // GetFileSettings cmd:  90 F5 00 00 01 01 00
        //                 rsp:  00 00 10 11 10 00 00 0C 38 70 35 84 D6 7E 10 91 00
        // ChangeFileSettings cmd: 90 5F 00 00 09 01 6A 40 3C 01 E8 88 23 2F 00
        //                   rsp: 10 CD 6F 8D C3 D3 42 B9 91 00
        let session_key = TwoKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x51, 0x99, 0x63, 0x96, 0x01, 0x02, 0x03, 0x04, 0x51, 0x99,
            0x63, 0x96,
        ]);
        let auth_session = AuthenticatedSession::new_2tdea(KeyNumber::new(0).unwrap(), session_key);

        let transport = MockTransport::new([
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x00, 0x10, 0x11, 0x10, 0x00, 0x00, 0x0C, 0x38, 0x70, 0x35, 0x84, 0xD6,
                    0x7E, 0x10, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0x5F, 0x00, 0x00, 0x09, 0x01, 0x6A, 0x40, 0x3C, 0x01, 0xE8, 0x88, 0x23,
                    0x2F, 0x00,
                ][..],
                &[0x10, 0xCD, 0x6F, 0x8D, 0xC3, 0xD3, 0x42, 0xB9, 0x91, 0x00][..],
            ),
        ]);

        let mut desfire = Desfire::new(transport, WrappedFraming);
        desfire.session = Session::Authenticated(auth_session);

        let key0 = AccessCondition::Key(KeyNumber::new(0).unwrap());
        let key1 = AccessCondition::Key(KeyNumber::new(1).unwrap());
        let access_rights = AccessRights::new(key1, key1, key1, key0);

        desfire.get_file_settings(FileId::new(1).unwrap()).unwrap();
        desfire
            .change_file_settings(
                FileId::new(1).unwrap(),
                CommunicationMode::Plain,
                access_rights,
            )
            .unwrap();

        assert_eq!(desfire.executor().transport().index, 2);
    }

    #[test]
    fn read_data_maced_2tdea_zero_key1_proxmark_trace() {
        // Proxmark3 trace: hf mfdes read --aid 222222 --fid 01 -n 1 -t 2tdea
        // Session key: 01 02 03 04 FC 67 24 71 01 02 03 04 FC 67 24 71
        // GetFileSettings cmd:  90 F5 00 00 01 01 00
        //                 rsp:  00 00 10 11 10 00 00 4F 25 14 78 C4 F0 66 FC 91 00
        // ReadData cmd:  90 BD 00 00 07 01 00 00 00 00 00 00 00 00
        //          rsp:  00*16 AF 4E 90 AE AE 3A DC F4 91 00
        let session_key = TwoKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0xFC, 0x67, 0x24, 0x71, 0x01, 0x02, 0x03, 0x04, 0xFC, 0x67,
            0x24, 0x71,
        ]);
        let auth_session = AuthenticatedSession::new_2tdea(KeyNumber::new(1).unwrap(), session_key);

        let transport = MockTransport::new([
            (
                &[0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00][..],
                &[
                    0x00, 0x00, 0x10, 0x11, 0x10, 0x00, 0x00, 0x4F, 0x25, 0x14, 0x78, 0xC4, 0xF0,
                    0x66, 0xFC, 0x91, 0x00,
                ][..],
            ),
            (
                &[
                    0x90, 0xBD, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0xAF, 0x4E, 0x90, 0xAE, 0xAE, 0x3A, 0xDC, 0xF4, 0x91, 0x00,
                ][..],
            ),
        ]);

        let mut desfire = Desfire::new(transport, WrappedFraming);
        desfire.session = Session::Authenticated(auth_session);

        let mut data: Vec<u8, 32> = Vec::new();
        desfire.get_file_settings(FileId::new(1).unwrap()).unwrap();
        desfire
            .read_data_maced(
                FileId::new(1).unwrap(),
                U24::new(0).unwrap(),
                U24::new(0).unwrap(),
                &mut data,
            )
            .unwrap();

        assert_eq!(data.as_slice(), &[0u8; 16]);
        assert_eq!(desfire.executor().transport().index, 2);
    }

    #[test]
    fn creates_application_unauthenticated() {
        let transport =
            MockTransport::new([(&[0xCA, 0x22, 0x22, 0x22, 0x0F, 0x81][..], &[0x00][..])]);
        let mut desfire = Desfire::new(transport, NativeFraming);

        let aid = crate::mifare::desfire::ApplicationId::new(0x22_22_22).unwrap();
        let ks = crate::mifare::desfire::KeySettings::new(0x0F, ApplicationKeyType::Aes, 1);

        desfire.create_application(aid, ks).unwrap();

        assert_eq!(desfire.executor().transport().index, 1);
    }

    #[test]
    fn changes_2tdea_app_key_different_key_proxmark_trace() {
        // Proxmark3 trace: hf mfdes changekey --aid 222222 -t 2tdea -n 0 --newkeyno 1 --verbose --apdu
        // Auth key 0: 2tdea zero key.  New/old key 1: 2tdea zero key.
        // Session key: 01 02 03 04 82 E4 29 94 01 02 03 04 82 E4 29 94
        // Command: 90 C4 00 00 19 01 13 85 5D BB EC 9A 5C CB BB 34 92 D8 97 98 DC 8D AE C7 52 BF ED 26 55 AF 00
        // Response: 2D 23 DD E4 FF 07 EB 0E 91 00
        let session_key = TwoKey3DesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x82, 0xE4, 0x29, 0x94, 0x01, 0x02, 0x03, 0x04, 0x82, 0xE4,
            0x29, 0x94,
        ]);
        let auth_session = AuthenticatedSession::new_2tdea(KeyNumber::new(0).unwrap(), session_key);

        let transport = MockTransport::new([(
            &[
                0x90, 0xC4, 0x00, 0x00, 0x19, 0x01, 0x13, 0x85, 0x5D, 0xBB, 0xEC, 0x9A, 0x5C, 0xCB,
                0xBB, 0x34, 0x92, 0xD8, 0x97, 0x98, 0xDC, 0x8D, 0xAE, 0xC7, 0x52, 0xBF, 0xED, 0x26,
                0x55, 0xAF, 0x00,
            ][..],
            &[0x2D, 0x23, 0xDD, 0xE4, 0xFF, 0x07, 0xEB, 0x0E, 0x91, 0x00][..],
        )]);

        let mut desfire = Desfire::new(transport, WrappedFraming);
        desfire.session = Session::Authenticated(auth_session);

        desfire
            .change_key_2tdea(KeyNumber::new(1).unwrap(), [0u8; 16], Some([0u8; 16]))
            .unwrap();

        assert!(matches!(desfire.session, Session::Authenticated(_)));
        assert_eq!(desfire.executor().transport().index, 1);
    }
}
