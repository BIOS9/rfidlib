use gallagher_rfid_acr122u::smart_card_reader::SmartCardReader;

fn main() {
    let readers: Vec<SmartCardReader> = match gallagher_rfid_acr122u::get_readers() {
        Ok(readers) => readers.collect(),
        Err(err) => {
            panic!("Failed to get smart card readers {}", err)
        }
    };

    for reader in &readers {
        println!("Found reader: {}", reader.name);
    }

    let acr122u = match readers.iter().find(|reader| reader.name.starts_with("ACS ACR122")) {
        Some(reader) => reader,
        None => {
            panic!("Failed to find ACR122u smart card reader!");
        }
    };
    
    println!("Using reader: {}", acr122u.name);

    
}
