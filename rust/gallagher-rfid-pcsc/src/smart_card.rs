use pcsc::{Card, MAX_BUFFER_SIZE};

use crate::error::SmartCardError;

pub struct SmartCard {
    pcsc_card: Card
}

impl SmartCard {
    pub(crate) fn new(pcsc_card: Card) -> Self {
        SmartCard { pcsc_card }
    }

    pub fn control(&mut self, control_code: u32, command: &[u8]) -> Result<Vec<u8>, SmartCardError> {
        let mut response_buff= [0; MAX_BUFFER_SIZE];
        match self.pcsc_card.control(control_code, &command, &mut response_buff) {
            Ok(response) => Ok(response.to_vec()),
            Err(err) => {
                Err(SmartCardError::CardCommunicateFailed(format!(
                    "Control command failed: {}", err
                )))
            }
        }
    }

    pub fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, SmartCardError> {
        let tx = self.pcsc_card.transaction()
            .map_err(|err| SmartCardError::CardCommunicateFailed(format!(
                "Failed to start card transaction: {}", err
            )))?;

        let mut response_buff = [0u8; MAX_BUFFER_SIZE];
        let response = tx.transmit(apdu, &mut response_buff)
            .map_err(|err| SmartCardError::CardCommunicateFailed(format!(
                "Failed to transceive card APDU: {}", err
            )))?;

        Ok(response.to_vec())
    }
}