use gallagher_rfid_core::mifare::{
    self,
    classic::{Block, KeyType, Sector, Tag},
};

use crate::smart_card::{self, SmartCard};

pub struct Acr122uCard {
    smart_card: SmartCard,
}

impl Acr122uCard {
    pub(crate) fn new(smart_card: SmartCard) -> Self {
        Acr122uCard { smart_card }
    }

    pub fn blink(&mut self) -> Result<(), smart_card::Error> {
        let blink = b"\xFF\x00\x40\x50\x04\x05\x05\x03\x01";

        _ = self.smart_card.transmit_apdu(blink)?;

        Ok(())
    }

    pub fn set_card_detect_beep(&mut self, beep: bool) -> Result<(), smart_card::Error> {
        let beep_byte = if beep { 0xFF } else { 0x00 };
        let beep_apdu = [0xFF, 0x00, 0x52, beep_byte, 0x00];

        let response = self.smart_card.transmit_apdu(&beep_apdu)?;

        return match response.as_slice() {
            [0x90, b] if *b == beep_byte => Ok(()),
            _ => Err(smart_card::Error::CardCommunicateFailed(format!(
                "Failed to disable card detect beep, reader returned: {:02X?}",
                response
            ))),
        };
    }
}

impl Tag for Acr122uCard {
    fn authenticate(
        &mut self,
        sector: Sector,
        key: [u8; 6],
        key_type: KeyType,
    ) -> Result<(), mifare::classic::Error> {
        // Load key into volatile memory (slot 0)
        let load_key_apdu: [u8; 11] = {
            let mut apdu = [0u8; 11];
            apdu[..5].copy_from_slice(&[0xFF, 0x82, 0x00, 0x00, 0x06]);
            apdu[5..].copy_from_slice(&key);
            apdu
        };
        match self.smart_card.transmit_apdu(&load_key_apdu)?.as_slice() {
            [0x90, 0x00] => Ok(()),
            [sw1, sw2] => Err(smart_card::Error::CardCommunicateFailed(format!(
                "Unexpected response when loading Mifare key SW1/SW2: {:02X} {:02X}",
                *sw1, *sw2
            ))),
            _ => Err(smart_card::Error::CardCommunicateFailed(
                "Unexpected response when loading Mifare key".to_string(),
            )),
        }?;

        // Authenticate to that block
        let key_type_code = match key_type {
            KeyType::KeyA => 0x60,
            KeyType::KeyB => 0x61,
        };
        let auth_apdu = [
            0xFF,
            0x86,
            0x00,
            0x00,
            0x05,
            0x01,
            0x00,
            Block::from(sector).into(),
            key_type_code,
            0x00,
        ];

        match self.smart_card.transmit_apdu(&auth_apdu)?.as_slice() {
            [0x90, 0x00] => Ok(()),
            [sw1, sw2] => Err(smart_card::Error::CardCommunicateFailed(format!(
                "Unexpected response when authenticating Mifare block SW1/SW2: {:02X} {:02X}",
                *sw1, *sw2
            ))),
            _ => Err(smart_card::Error::CardCommunicateFailed(
                "Unexpected response when authenticating Mifare block".to_string(),
            )),
        }?;

        Ok(())
    }

    fn read_block(&mut self, block: Block) -> Result<[u8; 16], mifare::classic::Error> {
        let apdu = [0xFF, 0xB0, 0x00, block.into(), 0x10];

        let response = self.smart_card.transmit_apdu(&apdu)?;
        match response.as_slice() {
            [data @ .., 0x90, 0x00] if data.len() == 16 => {
                let mut out = [0u8; 16];
                out.copy_from_slice(data);
                Ok(out)
            }
            [.., sw1, sw2] => Err(mifare::classic::Error::TransportError(format!(
                "Unexpected response when reading block {}: SW1/SW2 = {:02X} {:02X}",
                block, *sw1, *sw2,
            ))),
            _ => Err(mifare::classic::Error::TransportError(format!(
                "Invalid response length when reading block {}",
                block,
            ))),
        }
    }

    fn write_block(&mut self, block: Block, data: [u8; 16]) -> Result<(), mifare::classic::Error> {
        let mut apdu = [0u8; 21];
        apdu[..5].copy_from_slice(&[0xFF, 0xD6, 0x00, block.into(), 0x10]);
        apdu[5..].copy_from_slice(&data);

        let response = self.smart_card.transmit_apdu(&apdu)?;
        match response.as_slice() {
            [0x90, 0x00] => Ok(()),
            [sw1, sw2] => Err(mifare::classic::Error::TransportError(format!(
                "Unexpected response when writing block {}: SW1/SW2 = {:02X} {:02X}",
                block, *sw1, *sw2,
            ))),
            _ => Err(mifare::classic::Error::TransportError(format!(
                "Invalid response when writing block {}",
                block,
            ))),
        }
    }
}
