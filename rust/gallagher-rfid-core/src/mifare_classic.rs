use crate::mifare_classic_error::MifareClassicError;

#[derive(Debug, Clone, Copy)]
pub enum MifareClassicKeyType {
    KeyA,
    KeyB,
}


pub trait MifareClassic {
    /// Authenticate to a specific block using Key A or B.
    fn authenticate(
        &mut self,
        sector: u8,
        key: [u8; 6],
        key_type: MifareClassicKeyType,
    ) -> Result<(), MifareClassicError>;

    // /// Read 16 bytes from a block.
    // fn read_block(&mut self, block: u8) -> Result<[u8; 16], SmartCardError>;

    // /// Write 16 bytes to a block.
    // fn write_block(&mut self, block: u8, data: [u8; 16]) -> Result<(), SmartCardError>;
}

pub fn sector_to_block(sector: u8) -> Option<u8> {
    return sector_offset_to_block(sector, 0);
}

pub fn sector_offset_to_block(sector: u8, block_offset: u8) -> Option<u8> {
    match sector {
        0..=31 => {
            if block_offset <= 3 {
                Some(sector * 4 + block_offset)
            } else {
                None
            }
        }
        32..=39 => {
            if block_offset <= 15 {
                Some(((sector - 32) * 16) + 
                128 + 
                block_offset) // Mifare 4k has 16 block sectors for sector 32 and above.
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn block_to_sector(block: u8) -> u8 {
    if block < 128 {
        block / 4
    } else {
        ((block - 128) / 16) + 32
    }
}
