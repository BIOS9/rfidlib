pub mod native;
pub mod wrapped;

pub use native::NativeFraming;
pub use wrapped::WrappedFraming;

use crate::mifare::desfire::{
    command::{Command, Response},
    error::Error,
    transport::Frame,
};

/// Encodes and decodes one `DESFire` framing style.
pub trait FrameCodec {
    fn encode(&self, command: &Command, frame: &mut Frame) -> Result<(), Error>;
    fn decode(&self, frame: &[u8], response: &mut Response) -> Result<(), Error>;
}
