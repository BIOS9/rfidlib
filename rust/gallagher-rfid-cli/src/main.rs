use gallagher_rfid_pcsc::{acr122u::Acr122uReader, smart_card_context::SmartCardContext, smart_card_reader::SmartCardReader};

fn main() {
    let context = SmartCardContext::establish().unwrap();
    let readers: Vec<SmartCardReader> = context.get_readers().unwrap().collect();

    for reader in &readers {
        println!("Found reader: {}", reader.name);
    }

    let reader = match readers.into_iter().find(|reader| reader.name.starts_with("ACS ACR122")) {
        Some(reader) => reader,
        None => {
            panic!("Failed to find ACR122u smart card reader!");
        }
    };
    
    println!("Using reader: {}", reader.name);

    let acr122u = Acr122uReader::try_from(reader).unwrap();
    let mut acr122u_card = acr122u.connect_to_card().unwrap();
    acr122u_card.set_card_detect_beep(false).unwrap();
    
    // acr122u_card.blink();
    // acr122u_card.blink();
    // acr122u_card.blink();
}
