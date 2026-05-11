use crate::mifare::desfire::{
    command::{Command, Response},
    error::Error,
    framing::FrameCodec,
    status::Status,
    transport::Frame,
};

/// Native `DESFire` command framing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeFraming;

impl FrameCodec for NativeFraming {
    fn encode(&self, command: &Command, frame: &mut Frame) -> Result<(), Error> {
        frame.clear();
        frame
            .push(command.code().as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        frame
            .extend_from_slice(command.data())
            .map_err(|_| Error::CommandTooLong)
    }

    fn decode(&self, frame: &[u8], response: &mut Response) -> Result<(), Error> {
        let Some((&status, data)) = frame.split_first() else {
            return Err(Error::MalformedResponse);
        };
        response.set(Status::from(status), data)
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        command::{Command, CommandCode, Response},
        framing::{FrameCodec, NativeFraming},
        status::Status,
        transport::Frame,
    };

    #[test]
    fn encodes_native_command() {
        let command = Command::new(CommandCode::SELECT_APPLICATION, &[0x01, 0x02, 0x03]).unwrap();
        let mut frame = Frame::new();

        NativeFraming.encode(&command, &mut frame).unwrap();

        assert_eq!(frame.as_slice(), &[0x5A, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn decodes_native_response() {
        let mut response = Response::new(Status::OperationOk);

        NativeFraming
            .decode(&[0xAF, 0x01, 0x02, 0x03], &mut response)
            .unwrap();

        assert_eq!(response.status(), Status::AdditionalFrame);
        assert_eq!(response.data(), &[0x01, 0x02, 0x03]);
    }
}
