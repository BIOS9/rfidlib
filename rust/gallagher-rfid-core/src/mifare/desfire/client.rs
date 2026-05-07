use heapless::Vec;

use crate::mifare::desfire::{
    application::ApplicationId,
    command::{Command, CommandCode},
    crypto::{
        aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, desfire_crc32, AesSessionKey,
        DesfireMac, RndA, RndB,
    },
    error::Error,
    executor::Executor,
    file::{FileId, FileSettings},
    framing::FrameCodec,
    key::{KeyNumber, KeySettings},
    session::{AuthenticatedSession, Session, SessionKey},
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

    /// Reads key settings for the currently selected application.
    pub fn get_key_settings(&mut self) -> Result<KeySettings, Error> {
        let command = Command::new(CommandCode::GET_KEY_SETTINGS, &[])?;
        let mut data: Vec<u8, 2> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        KeySettings::parse(data.as_slice())
    }

    /// Reads one key version from the currently selected application.
    pub fn get_key_version(&mut self, key_number: KeyNumber) -> Result<u8, Error> {
        let command = Command::new(CommandCode::GET_KEY_VERSION, &[key_number.as_byte()])?;
        let mut data: Vec<u8, 1> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        data.first().copied().ok_or(Error::InvalidResponseLength)
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

        session.update_command_cmac(command.code(), command.data())?;
        let iv = session.cmac_chaining().state();
        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }
        if response.data().len() < 16 || !response.data().len().is_multiple_of(16) {
            return Err(Error::InvalidResponseLength);
        }

        let SessionKey::Aes(session_key) = session.session_key();
        let mut decrypted: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        decrypted
            .extend_from_slice(response.data())
            .map_err(|_| Error::ResponseTooLong)?;
        let last_ciphertext_block: [u8; 16] = response.data()[response.data().len() - 16..]
            .try_into()
            .expect("slice length is checked");

        aes_cbc_decrypt_in_place(&session_key.as_bytes(), &iv, decrypted.as_mut_slice());
        let plaintext_len = encrypted_read_plaintext_len(
            decrypted.as_slice(),
            usize::try_from(length.as_u32()).expect("U24 fits in usize"),
            response.status(),
        )?;

        data.clear();
        data.extend_from_slice(&decrypted.as_slice()[..plaintext_len])
            .map_err(|_| Error::ResponseTooLong)?;

        session.set_chaining_state(last_ciphertext_block);
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
        // Response may contain a MAC if authenticated; ignored for plain writes.
        let mut ignored: Vec<u8, 8> = Vec::new();
        self.executor.execute(&command, &mut ignored)
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
        let SessionKey::Aes(session_key) = session.session_key();

        // IV = current chaining state (no command CMAC update for enciphered writes).
        let iv = session.cmac_chaining().state();

        // CRC covers the full command payload: [cmd_code || header || data].
        // Plaintext: [data || CRC32(cmd_code||header||data)] zero-padded to 16-byte boundary
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
        let crc = desfire_crc32(crc_input.as_slice());

        let mut plaintext: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        plaintext
            .extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        plaintext
            .extend_from_slice(&crc)
            .map_err(|_| Error::CommandTooLong)?;
        while plaintext.len() % 16 != 0 {
            plaintext.push(0x00).map_err(|_| Error::CommandTooLong)?;
        }

        aes_cbc_encrypt_in_place(&session_key.as_bytes(), &iv, plaintext.as_mut_slice());
        let last_ciphertext_block: [u8; 16] = plaintext.as_slice()[plaintext.len() - 16..]
            .try_into()
            .expect("slice length is checked");

        // Build command: [header || ciphertext].
        let mut cmd_data: Vec<u8, MAX_FRAME_SIZE> = Vec::new();
        cmd_data
            .extend_from_slice(header.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        cmd_data
            .extend_from_slice(plaintext.as_slice())
            .map_err(|_| Error::CommandTooLong)?;
        let command = Command::new(CommandCode::WRITE_DATA, cmd_data.as_slice())?;

        // Last ciphertext block becomes the new chaining state for response MAC verification.
        session.set_chaining_state(last_ciphertext_block);

        let response = self.executor.exchange_one(&command)?;
        if response.status() != Status::OperationOk {
            return Err(Error::Status(response.status()));
        }

        verify_response_mac(&mut session, Status::OperationOk, response.data())?;
        self.session = Session::Authenticated(session);
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

fn write_data_command_header(
    file_id: FileId,
    offset: U24,
    data: &[u8],
) -> Result<Vec<u8, 7>, Error> {
    let length = U24::new(data.len() as u32).ok_or(Error::CommandTooLong)?;
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
    if data.len() < 8 {
        return Err(Error::InvalidResponseLength);
    }

    let (body, mac) = data.split_at(data.len() - 8);
    let mac = DesfireMac::new(mac.try_into().expect("split size is checked"));
    if session.update_response_cmac(status, body)? != mac {
        return Err(Error::InvalidMac);
    }

    Ok(body)
}

fn encrypted_read_plaintext_len(
    decrypted: &[u8],
    requested_length: usize,
    status: Status,
) -> Result<usize, Error> {
    if requested_length == 0 {
        return infer_encrypted_read_plaintext_len(decrypted, status);
    }

    validate_encrypted_read_plaintext_len(decrypted, requested_length, status)
}

fn infer_encrypted_read_plaintext_len(decrypted: &[u8], status: Status) -> Result<usize, Error> {
    for plaintext_len in (0..=decrypted.len().saturating_sub(4)).rev() {
        if validate_encrypted_read_plaintext_len(decrypted, plaintext_len, status).is_ok() {
            return Ok(plaintext_len);
        }
    }

    Err(Error::InvalidCrc)
}

fn validate_encrypted_read_plaintext_len(
    decrypted: &[u8],
    plaintext_len: usize,
    status: Status,
) -> Result<usize, Error> {
    let crc_start = plaintext_len;
    let crc_end = crc_start + 4;
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

    if desfire_crc32(crc_data.as_slice()) != decrypted[crc_start..crc_end] {
        return Err(Error::InvalidCrc);
    }

    Ok(plaintext_len)
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
        client::Desfire,
        crypto::{aes_cbc_encrypt_in_place, AesSessionKey, RndA, RndB},
        error::Error,
        file::{CommunicationMode, FileId, FileSettingsDetails},
        framing::{NativeFraming, WrappedFraming},
        key::{ApplicationKeyType, KeyNumber},
        session::{Session, SessionKey},
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

    struct DynMockTransport {
        exchanges: std::vec::Vec<(std::vec::Vec<u8>, std::vec::Vec<u8>)>,
        index: usize,
    }

    impl DynMockTransport {
        fn new(exchanges: std::vec::Vec<(std::vec::Vec<u8>, std::vec::Vec<u8>)>) -> Self {
            Self {
                exchanges,
                index: 0,
            }
        }
    }

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
}
