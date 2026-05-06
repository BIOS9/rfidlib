use heapless::Vec;

use crate::mifare::desfire::error::Error;

/// Default frame capacity for short `DESFire` exchanges.
pub const MAX_FRAME_SIZE: usize = 256;

/// Fixed-capacity frame buffer used by `DESFire` transports and framers.
pub type Frame = Vec<u8, MAX_FRAME_SIZE>;

/// Raw byte exchange with a DESFire-capable transport.
///
/// Implementations may be PC/SC, Android `IsoDep`, PN532, or another ISO-DEP
/// path. `DESFire` command framing is intentionally kept out of this trait.
pub trait Transport {
    fn transceive(&mut self, tx: &[u8], rx: &mut Frame) -> Result<(), Error>;
}
