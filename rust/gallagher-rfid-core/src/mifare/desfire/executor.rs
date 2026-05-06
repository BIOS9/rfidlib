use heapless::Vec;

use crate::mifare::desfire::{
    command::{Command, Response},
    error::Error,
    framing::FrameCodec,
    status::Status,
    transport::{Frame, Transport},
};

/// Upper bound for chained `DESFire` continuation frames.
pub const MAX_ADDITIONAL_FRAMES: usize = 64;

/// Sends canonical `DESFire` commands through a transport and framing codec.
pub struct Executor<T, C> {
    transport: T,
    codec: C,
}

impl<T, C> Executor<T, C>
where
    T: Transport,
    C: FrameCodec,
{
    /// Creates an executor from a byte transport and frame codec.
    pub const fn new(transport: T, codec: C) -> Self {
        Self { transport, codec }
    }

    /// Returns a shared reference to the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the executor and returns its transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Sends one framed command and decodes one response frame.
    pub fn exchange_one(&mut self, command: &Command) -> Result<Response, Error> {
        let mut tx = Frame::new();
        let mut rx = Frame::new();
        let mut response = Response::new(Status::OperationOk);

        self.codec.encode(command, &mut tx)?;
        self.transport.transceive(tx.as_slice(), &mut rx)?;
        self.codec.decode(rx.as_slice(), &mut response)?;

        Ok(response)
    }

    /// Executes a command and collects all `AdditionalFrame` response data.
    pub fn execute<const N: usize>(
        &mut self,
        command: &Command,
        data: &mut Vec<u8, N>,
    ) -> Result<(), Error> {
        data.clear();

        let mut response = self.exchange_one(command)?;
        let mut additional_frames = 0;

        loop {
            match response.status() {
                Status::OperationOk => {
                    append_response_data(data, response.data())?;
                    return Ok(());
                }
                Status::AdditionalFrame => {
                    append_response_data(data, response.data())?;
                    additional_frames += 1;
                    if additional_frames > MAX_ADDITIONAL_FRAMES {
                        return Err(Error::TooManyAdditionalFrames);
                    }
                    response = self.exchange_one(&Command::additional_frame())?;
                }
                status => return Err(Error::Status(status)),
            }
        }
    }
}

fn append_response_data<const N: usize>(out: &mut Vec<u8, N>, chunk: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(chunk)
        .map_err(|_| Error::ResponseTooLong)
}

#[cfg(test)]
mod tests {
    use heapless::Vec;

    use crate::mifare::desfire::{
        command::{Command, CommandCode},
        error::Error,
        executor::Executor,
        framing::{NativeFraming, WrappedFraming},
        status::Status,
        transport::{Frame, Transport},
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
    fn executes_single_native_frame() {
        let transport = MockTransport::new([(&[0x60][..], &[0x00, 0x04, 0x01][..])]);
        let mut executor = Executor::new(transport, NativeFraming);
        let command = Command::new(CommandCode::GET_VERSION, &[]).unwrap();
        let mut data: Vec<u8, 8> = Vec::new();

        executor.execute(&command, &mut data).unwrap();

        assert_eq!(data.as_slice(), &[0x04, 0x01]);
        assert_eq!(executor.transport().index, 1);
    }

    #[test]
    fn follows_wrapped_additional_frames() {
        let transport = MockTransport::new([
            (
                &[0x90, 0x60, 0x00, 0x00, 0x00][..],
                &[0x01, 0x02, 0x91, 0xAF][..],
            ),
            (
                &[0x90, 0xAF, 0x00, 0x00, 0x00][..],
                &[0x03, 0x04, 0x91, 0x00][..],
            ),
        ]);
        let mut executor = Executor::new(transport, WrappedFraming);
        let command = Command::new(CommandCode::GET_VERSION, &[]).unwrap();
        let mut data: Vec<u8, 8> = Vec::new();

        executor.execute(&command, &mut data).unwrap();

        assert_eq!(data.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(executor.transport().index, 2);
    }

    #[test]
    fn returns_non_success_status() {
        let transport = MockTransport::new([(&[0x6F][..], &[0x9D][..])]);
        let mut executor = Executor::new(transport, NativeFraming);
        let command = Command::new(CommandCode::GET_FILE_IDS, &[]).unwrap();
        let mut data: Vec<u8, 8> = Vec::new();

        let error = executor.execute(&command, &mut data).unwrap_err();

        assert_eq!(error, Error::Status(Status::PermissionDenied));
        assert!(data.is_empty());
    }

    #[test]
    fn rejects_response_larger_than_output_buffer() {
        let transport = MockTransport::new([(&[0x60][..], &[0x00, 0x01, 0x02, 0x03][..])]);
        let mut executor = Executor::new(transport, NativeFraming);
        let command = Command::new(CommandCode::GET_VERSION, &[]).unwrap();
        let mut data: Vec<u8, 2> = Vec::new();

        let error = executor.execute(&command, &mut data).unwrap_err();

        assert_eq!(error, Error::ResponseTooLong);
    }
}
