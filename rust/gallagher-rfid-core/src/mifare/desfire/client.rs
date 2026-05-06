use heapless::Vec;

use crate::mifare::desfire::{
    application::ApplicationId,
    command::{Command, CommandCode},
    crypto::{aes_cbc_decrypt_in_place, aes_cbc_encrypt_in_place, AesSessionKey, RndA, RndB},
    error::Error,
    executor::Executor,
    file::{FileId, FileSettings},
    framing::FrameCodec,
    key::{KeyNumber, KeySettings},
    session::AuthenticatedSession,
    status::Status,
    transport::Transport,
    types::U24,
    version::VersionInfo,
};

/// High-level `DESFire` command client.
pub struct Desfire<T, C> {
    executor: Executor<T, C>,
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
        }
    }

    /// Creates a client from an existing executor.
    pub const fn from_executor(executor: Executor<T, C>) -> Self {
        Self { executor }
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

    /// Reads and parses the card version information.
    pub fn get_version(&mut self) -> Result<VersionInfo, Error> {
        let command = Command::new(CommandCode::GET_VERSION, &[])?;
        let mut data: Vec<u8, 28> = Vec::new();

        self.executor.execute(&command, &mut data)?;
        VersionInfo::parse(data.as_slice())
    }

    /// Performs legacy AES authentication with caller-provided reader randomness.
    ///
    /// This establishes the session key but does not yet enable `MACed` or
    /// enciphered secure messaging for later commands.
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
        Ok(AuthenticatedSession::new_aes(key_number, session_key))
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

        self.executor.execute(&command, &mut data)
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

        self.executor.execute(&command, &mut data)?;
        FileSettings::parse(data.as_slice())
    }

    /// Reads bytes from a standard or backup data file.
    pub fn read_data<const N: usize>(
        &mut self,
        file_id: FileId,
        offset: U24,
        length: U24,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
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

        let command = Command::new(CommandCode::READ_DATA, command_data.as_slice())?;
        self.executor.execute(&command, data)
    }
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
        file::{FileId, FileSettingsDetails},
        framing::{NativeFraming, WrappedFraming},
        key::{ApplicationKeyType, KeyNumber},
        session::SessionKey,
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

        let transport = OwnedMockTransport::new([
            (first_command, 2, first_response_padded, 17),
            (second_command, 33, second_response_padded, 17),
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
