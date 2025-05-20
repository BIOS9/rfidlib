use gallagher_rfid_core::mifare::classic::{MifareClassic, MifareClassicKeyType};
use gallagher_rfid_pcsc::{
    acr122u::Acr122uReader, smart_card_context::SmartCardContext,
    smart_card_reader::SmartCardReader,
};
fn main() {
    let context = SmartCardContext::establish().unwrap();
    let readers: Vec<SmartCardReader> = context.get_readers().unwrap().collect();

    for reader in &readers {
        println!("Found reader: {}", reader.name);
    }

    let reader = match readers
        .into_iter()
        .find(|reader| reader.name.starts_with("ACS ACR122"))
    {
        Some(reader) => reader,
        None => {
            panic!("Failed to find ACR122u smart card reader!");
        }
    };

    println!("Using reader: {}", reader.name);

    let acr122u = Acr122uReader::try_from(reader).unwrap();
    let mut acr122u_card = acr122u.connect_to_card().unwrap();
    acr122u_card.set_card_detect_beep(false).unwrap();
    acr122u_card
        .authenticate(
            0.into(),
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            MifareClassicKeyType::KeyA,
        )
        .unwrap();
    // acr122u_card.authenticate(0, [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], MifareClassicKeyType::KeyA).unwrap();
    let block: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
    acr122u_card
        .write_block(1.try_into().unwrap(), block)
        .unwrap();
    let block = acr122u_card.read_block(1.try_into().unwrap());
    println!("Block data: {:02X?}", block);
    // acr122u_card.blink();
    // acr122u_card.blink();
    // acr122u_card.blink();
}
