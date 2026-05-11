use crate::mifare::classic::{Block, Sector};

/// Represents which MIFARE Classic key to use for authentication.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    KeyA,
    KeyB,
}

/// Trait defining basic operations for interacting with MIFARE Classic tags.
pub trait Tag {
    // Default MIFARE Classic A and B sector key.
    const DEFAULT_KEY: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    /// Authenticate to a specific sector on the tag using Key A or B.
    fn authenticate(
        &mut self,
        sector: Sector,
        key: &[u8; 6],
        key_type: KeyType,
    ) -> Result<(), Error>;

    /// Reads a 16-byte data block from the tag.
    fn read_block(&mut self, block: Block) -> Result<[u8; 16], Error>;

    /// Writes a 16-byte data block to the tag.
    fn write_block(&mut self, block: Block, data: [u8; 16]) -> Result<(), Error>;
}

/// Represents errors that can occur during MIFARE Classic operations.
#[derive(Debug)]
pub enum Error {
    /// Failed to authenticate to a sector.
    AuthenticationFailed(Sector),

    /// Invalid value for a MIFARE classic sector.
    InvalidSector(u8),

    /// Invalid value for a MIFARE classic block.
    InvalidBlock(u8),

    /// Low-level PCSC or transport error.
    #[cfg(feature = "std")]
    TransportError(std::string::String),
    #[cfg(not(feature = "std"))]
    TransportError(heapless::String<64>),
}

/// Trait for providing authentication to MIFARE Classic sectors.
///
/// Used to abstract how keys are retrieved and applied for authentication.
pub trait KeyProvider {
    fn authenticate<T: Tag>(&self, tag: &mut T, sector: Sector) -> Result<(), Error>;
}
