use gallagher_rfid_core::{mifare_classic::{sector_to_block, MifareClassic, MifareClassicKeyType}, mifare_classic_error::MifareClassicError};

use crate::{error::SmartCardError, smart_card::SmartCard};

pub struct Acr122uCard {
    smart_card: SmartCard
}

impl Acr122uCard {
    pub(crate) fn new(smart_card: SmartCard) -> Self {
        Acr122uCard { smart_card }
    }

    pub fn blink(&mut self) -> Result<(), SmartCardError>{
        let blink = b"\xFF\x00\x40\x50\x04\x05\x05\x03\x01";

        let response = self.smart_card.transmit_apdu(blink)?;

        Ok(())
    }

    pub fn set_card_detect_beep(&mut self, beep: bool) -> Result<(), SmartCardError> {
        let beep_byte = if beep { 0xFF } else { 0x00 };
        let beep_apdu = [0xFF, 0x00, 0x52, beep_byte, 0x00];

        let response = self.smart_card.transmit_apdu(&beep_apdu)?;

        return match response.as_slice() {
            [0x90, b] if *b == beep_byte => Ok(()),
            _ => Err(SmartCardError::CardCommunicateFailed(format!(
                "Failed to disable card detect beep, reader returned: {:02X?}", response)))
        }
    }
}

impl MifareClassic for Acr122uCard {
    fn authenticate(
        &mut self,
        sector: u8,
        key: [u8; 6],
        key_type: MifareClassicKeyType,
    ) -> Result<(), MifareClassicError> {
         let block = sector_to_block(sector)
            .ok_or(MifareClassicError::InvalidSector(sector))?;

        // Load key into volatile memory (slot 0)
       let load_key_apdu: [u8; 11] = {
            let mut apdu = [0u8; 11];
            apdu[..5].copy_from_slice(&[0xFF, 0x82, 0x00, 0x00, 0x06]);
            apdu[5..].copy_from_slice(&key);
            apdu
        };
        match self.smart_card.transmit_apdu(&load_key_apdu)?.as_slice() {
            [0x90, 0x00] => Ok(()),
            [sw1, sw2] => Err(SmartCardError::CardCommunicateFailed(format!("Unexpected response when loading Mifare key SW1/SW2: {:02X} {:02X}", *sw1, *sw2))),
            _ => Err(SmartCardError::CardCommunicateFailed("Unexpected response when loading Mifare key".to_string()))
        }?;

        // Authenticate to that block
        let key_type_code = match key_type {
            MifareClassicKeyType::KeyA => 0x60,
            MifareClassicKeyType::KeyB => 0x61,
        };
        let auth_apdu = [
            0xFF, 0x86, 0x00, 0x00, 0x05,
            0x01, 0x00, block,
            key_type_code, 0x00
        ];

        match self.smart_card.transmit_apdu(&auth_apdu)?.as_slice() {
            [0x90, 0x00] => Ok(()),
            [sw1, sw2] => Err(SmartCardError::CardCommunicateFailed(format!("Unexpected response when authenticating Mifare block SW1/SW2: {:02X} {:02X}", *sw1, *sw2))),
            _ => Err(SmartCardError::CardCommunicateFailed("Unexpected response when authenticating Mifare block".to_string()))
        }?;

        Ok(())
    }
}
