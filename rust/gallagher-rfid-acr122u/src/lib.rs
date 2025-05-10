use error::SmartCardError;
use gallagher_rfid_core::{transport::RfidTransport, error::RfidError};
use pcsc::{Context, Scope};
use smart_card_reader::SmartCardReader;

pub mod smart_card_reader;
pub mod error;

pub fn get_readers() -> Result<impl Iterator<Item = SmartCardReader>, SmartCardError>{
    let ctx = Context::establish(Scope::User)
        .map_err(|err| SmartCardError::ContextInitFailed(format!(
            "Failed to initialize PCSC smart card context: {}", err)))?;

    let reader_names_size = ctx.list_readers_len()
        .map_err(|err| SmartCardError::ReaderListFailed(format!(
            "Failed to get size of reader string: {}", err)))?;

    let mut reader_names_buf = vec![0u8; reader_names_size];
    let reader_names: Vec<String> = ctx.list_readers(&mut reader_names_buf)
        .map_err(|err| SmartCardError::ReaderListFailed(format!(
            "Failed to get smart card readers: {}", err)))?
        .map(|name| name.to_string_lossy().to_string())
        .collect();
    
    let readers = reader_names
        .into_iter()
        .map(|name| SmartCardReader{ name });

    Ok(readers)
}
