use crate::{error::SmartCardError, smart_card_reader::SmartCardReader};

pub struct SmartCardContext {
    pcsc_context: pcsc::Context,
}

impl SmartCardContext {
    pub(crate) fn get_pcsc_context(&self) -> &pcsc::Context {
        &self.pcsc_context
    }

    pub fn establish() -> Result<SmartCardContext, SmartCardError> {
        match pcsc::Context::establish(pcsc::Scope::User) {
            Ok(pcsc_context) => Ok(SmartCardContext { pcsc_context }),
            Err(err) => Err(SmartCardError::ContextInitFailed(format!(
                "Failed to initialize PCSC smart card context: {}",
                err
            ))),
        }
    }

    pub fn get_readers(&self) -> Result<impl Iterator<Item = SmartCardReader>, SmartCardError> {
        let reader_c_names = self
            .pcsc_context
            .list_readers_owned()
            .map_err(|err| {
                SmartCardError::ReaderListFailed(format!(
                    "Failed to get smart card readers: {}",
                    err
                ))
            })?
            .into_iter();

        let reader_names: Vec<String> = reader_c_names
            .map(|name| {
                let s = name.to_str().map_err(|err| {
                    SmartCardError::ReaderListFailed(format!(
                        "Failed to convert reader name to valid UTF-8 string: {}",
                        err
                    ))
                })?;
                Ok(s.to_owned())
            })
            .collect::<Result<_, _>>()?;

        let readers = reader_names
            .into_iter()
            .map(|name| SmartCardReader::new(name, self));

        Ok(readers)
    }
}
