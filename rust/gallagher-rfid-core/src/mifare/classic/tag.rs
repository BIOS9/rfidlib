use std::string::String;

use super::{block::Block, sector::Sector};

/// Represents which MIFARE Classic key to use for authentication.
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    KeyA,
    KeyB,
}

/// Trait defining basic operations for interacting with MIFARE Classic tags.
pub trait Tag {
    /// Authenticate to a specific sector on the tag using Key A or B.
    fn authenticate(
        &mut self,
        sector: Sector,
        key: [u8; 6],
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
    TransportError(String),
}

/// Trait for providing authentication to MIFARE Classic sectors.
///
/// Used to abstract how keys are retrieved and applied for authentication.
pub trait KeyProvider {
    fn authenticate<T: Tag>(&self, tag: T, sector: Sector) -> Result<(), Error>;
}
