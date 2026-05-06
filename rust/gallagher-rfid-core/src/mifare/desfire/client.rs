use heapless::Vec;

use crate::mifare::desfire::{
    application::ApplicationId,
    command::{Command, CommandCode},
    error::Error,
    executor::Executor,
    file::{FileId, FileSettings},
    framing::FrameCodec,
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
        error::Error,
        file::{FileId, FileSettingsDetails},
        framing::NativeFraming,
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
