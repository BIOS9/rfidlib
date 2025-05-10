use std::ffi::CString;

use pcsc::{ShareMode, Protocols};
use crate::{error::SmartCardError, smart_card::SmartCard, smart_card_context::SmartCardContext};

pub struct SmartCardReader<'a> {
    pub name: String,
    context: &'a SmartCardContext
}

impl<'a> SmartCardReader<'a> {
    pub(crate) fn new(name: String, context: &'a SmartCardContext) -> Self {
        SmartCardReader { name, context }
    }

    pub fn connect_to_card(&self) -> Result<SmartCard, SmartCardError> {
        let pcsc_context = self.context.get_pcsc_context();

        let c_name = CString::new(self.name.clone())
            .map_err(|err| SmartCardError::CardConnectFailed(format!(
                "Reader name contains null byte: {}", err
            )))?;
        
        match pcsc_context.connect(c_name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
            Ok(pcsc_card) => Ok(SmartCard::new(pcsc_card)),
            Err(pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard) => {
                Err(SmartCardError::CardConnectFailed(
                    "Smart card not present in the reader".to_string()
                ))
            }
            Err(err) => Err(SmartCardError::CardConnectFailed(format!(
                "Failed to connect to smart card: {}", err
            ))),
        }
    }
}
