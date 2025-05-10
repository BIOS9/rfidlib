use crate::{acr122u_card::Acr122uCard, error::SmartCardError, smart_card_reader::SmartCardReader};

pub struct Acr122uReader<'a> {
    reader: SmartCardReader<'a>
}

impl<'a> Acr122uReader<'a> {
    pub(crate) fn new(reader: SmartCardReader<'a>) -> Self {
        Acr122uReader { reader }
    }

    pub fn connect_to_card(&self) -> Result<Acr122uCard, SmartCardError> {
        let smart_card = self.reader.connect_to_card()?;
        Ok(Acr122uCard::new(smart_card))
    }
}

impl<'a> TryFrom<SmartCardReader<'a>> for Acr122uReader<'a> {
    type Error = SmartCardError;

    fn try_from(reader: SmartCardReader<'a>) -> Result<Self, Self::Error> {
        let mut card = reader.connect_to_card()?;
        let get_firmware_version = b"\xFF\x00\x48\x00\x00";
        let response = card.transmit_apdu(get_firmware_version)?;

        let firmware = String::from_utf8_lossy(&response);
        if firmware.starts_with("ACR122U") {
            Ok(Acr122uReader::new(reader))
        } else {
            Err(SmartCardError::UnsupportedReader(format!(
                "Unexpected firmware version for ACR122u: {}", firmware
            )))
        }

    }
}