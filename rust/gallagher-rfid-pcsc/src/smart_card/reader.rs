use std::ffi::CString;

use crate::smart_card::{Error, SmartCard, SmartCardContext};
use pcsc::{Protocols, ShareMode};

pub struct SmartCardReader<'a> {
    pub name: String,
    context: &'a SmartCardContext,
}

impl<'a> SmartCardReader<'a> {
    pub(crate) fn new(name: String, context: &'a SmartCardContext) -> Self {
        SmartCardReader { name, context }
    }

    pub fn connect_to_card(&self) -> Result<SmartCard, Error> {
        let pcsc_context = self.context.get_pcsc_context();

        let c_name = CString::new(self.name.clone()).map_err(|err| {
            Error::CardConnectFailed(format!("Reader name contains null byte: {}", err))
        })?;

        match pcsc_context.connect(c_name.as_c_str(), ShareMode::Exclusive, Protocols::ANY) {
            Ok(pcsc_card) => Ok(SmartCard::new(pcsc_card)),
            Err(pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard) => Err(
                Error::CardConnectFailed("Smart card not present in the reader".to_string()),
            ),
            Err(err) => Err(Error::CardConnectFailed(format!(
                "Failed to connect to smart card: {}",
                err
            ))),
        }
    }
}
