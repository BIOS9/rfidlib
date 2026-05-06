use crate::mifare::desfire::{
    command::{Command, Response},
    error::Error,
    framing::FrameCodec,
    status::Status,
    transport::Frame,
};

/// ISO 7816 APDU wrapper for native `DESFire` commands.
#[derive(Debug, Clone, Copy, Default)]
pub struct WrappedFraming;

impl FrameCodec for WrappedFraming {
    fn encode(&self, command: &Command, frame: &mut Frame) -> Result<(), Error> {
        let payload_len = u8::try_from(command.data().len()).map_err(|_| Error::CommandTooLong)?;

        frame.clear();
        frame
            .extend_from_slice(&[0x90, command.code().as_byte(), 0x00, 0x00, payload_len])
            .map_err(|_| Error::CommandTooLong)?;
        frame
            .extend_from_slice(command.data())
            .map_err(|_| Error::CommandTooLong)?;
        frame.push(0x00).map_err(|_| Error::CommandTooLong)
    }

    fn decode(&self, frame: &[u8], response: &mut Response) -> Result<(), Error> {
        let Some((&status, rest)) = frame.split_last() else {
            return Err(Error::MalformedResponse);
        };
        let Some((&marker, data)) = rest.split_last() else {
            return Err(Error::MalformedResponse);
        };
        if marker != 0x91 {
            return Err(Error::InvalidWrappedResponse);
        }
        response.set(Status::from(status), data)
    }
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        command::{Command, CommandCode, Response},
        error::Error,
        framing::{FrameCodec, WrappedFraming},
        status::Status,
        transport::Frame,
    };

    #[test]
    fn encodes_wrapped_command() {
        let command = Command::new(CommandCode::SELECT_APPLICATION, &[0x01, 0x02, 0x03]).unwrap();
        let mut frame = Frame::new();

        WrappedFraming.encode(&command, &mut frame).unwrap();

        assert_eq!(
            frame.as_slice(),
            &[0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00]
        );
    }

    #[test]
    fn decodes_wrapped_response() {
        let mut response = Response::new(Status::OperationOk);

        WrappedFraming
            .decode(&[0x01, 0x02, 0x03, 0x91, 0x00], &mut response)
            .unwrap();

        assert_eq!(response.status(), Status::OperationOk);
        assert_eq!(response.data(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn rejects_response_without_wrapped_marker() {
        let mut response = Response::new(Status::OperationOk);

        let error = WrappedFraming
            .decode(&[0x01, 0x02, 0x03, 0x90, 0x00], &mut response)
            .unwrap_err();

        assert_eq!(error, Error::InvalidWrappedResponse);
    }
}
