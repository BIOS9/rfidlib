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