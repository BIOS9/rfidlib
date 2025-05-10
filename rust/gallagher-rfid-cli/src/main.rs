use gallagher_rfid_acr122u::{smart_card_context::SmartCardContext, smart_card_reader::SmartCardReader};

fn main() {
    let context = SmartCardContext::establish().unwrap();
    let readers: Vec<SmartCardReader> = context.get_readers().unwrap().collect();

    for reader in &readers {
        println!("Found reader: {}", reader.name);
    }

    let reader = match readers.iter().find(|reader| reader.name.starts_with("ACS ACR122")) {
        Some(reader) => reader,
        None => {
            panic!("Failed to find ACR122u smart card reader!");
        }
    };
    
    println!("Using reader: {}", reader.name);

    let card = reader.connect_to_card().unwrap();
}
