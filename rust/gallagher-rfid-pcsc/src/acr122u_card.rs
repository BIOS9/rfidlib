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
}