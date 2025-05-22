use crate::smart_card::Error;
use pcsc::{Card, MAX_BUFFER_SIZE};

pub struct SmartCard {
    pcsc_card: Card,
}

impl SmartCard {
    pub(crate) fn new(pcsc_card: Card) -> Self {
        SmartCard { pcsc_card }
    }

    pub fn get_vendor(&mut self) -> Result<String, Error> {
        let result = self
            .pcsc_card
            .get_attribute_owned(pcsc::Attribute::VendorName);
        match result {
            Ok(v) => Ok(String::from_utf8_lossy(&v).to_string()),
            Err(err) => Err(Error::CardCommunicateFailed(format!(
                "Failed to query reader vendor: {}",
                err
            ))),
        }
    }

    pub fn control(&mut self, control_code: u32, command: &[u8]) -> Result<Vec<u8>, Error> {
        let mut response_buff = [0; MAX_BUFFER_SIZE];
        match self
            .pcsc_card
            .control(control_code, &command, &mut response_buff)
        {
            Ok(response) => Ok(response.to_vec()),
            Err(err) => Err(Error::CardCommunicateFailed(format!(
                "Control command failed: {}",
                err
            ))),
        }
    }

    pub fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let mut response_buff = [0u8; MAX_BUFFER_SIZE];
        let response = self
            .pcsc_card
            .transmit(apdu, &mut response_buff)
            .map_err(|err| {
                Error::CardCommunicateFailed(format!("Failed to transceive card APDU: {}", err))
            })?;

        Ok(response.to_vec())
    }
}
