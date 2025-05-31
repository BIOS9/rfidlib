use gallagher_rfid_core::mifare::application_directory::MadAid;
use gallagher_rfid_core::mifare::{
    application_directory::MifareApplicationDirectory,
    classic::{KeyProvider, KeyType, Tag},
};
use gallagher_rfid_pcsc::{
    acr122u::Acr122uReader,
    smart_card::{SmartCardContext, SmartCardReader},
};

struct SimpleKeyProvider {}
impl KeyProvider for SimpleKeyProvider {
    fn authenticate<T: Tag>(
        &self,
        tag: &mut T,
        sector: gallagher_rfid_core::mifare::classic::Sector,
    ) -> Result<(), gallagher_rfid_core::mifare::classic::Error> {
        tag.authenticate(sector, &[0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], KeyType::KeyA)
    }
}

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

    let mad = MifareApplicationDirectory::read_from_tag(&mut acr122u_card, &SimpleKeyProvider {})
        .unwrap();

    println!("Valid MADv{}", mad.mad_version as u8);
    for (sector, app) in mad.iter_applications() {
        match app {
            MadAid::CardAdministration(admin_code) => {
                println!(
                    "Sector: {}, Administration code: {}",
                    u8::from(sector),
                    admin_code as u8
                );
            }
            MadAid::Application(fc, app) => {
                println!(
                    "Sector: {}, App: FC: {}, App: {}",
                    u8::from(sector),
                    fc as u8,
                    app
                );
            }
            MadAid::Reserved(fc, app) => {
                println!(
                    "Sector: {}, Reserved: A: {}, B: {}",
                    u8::from(sector),
                    fc,
                    app
                );
            }
        }
    }

    // let sector = FourBlockSector::S1;
    // acr122u_card
    //     .authenticate(sector.into(), Acr122uCard::DEFAULT_KEY, KeyType::KeyA)
    //     .unwrap();
    // // acr122u_card.authenticate(0, [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], MifareClassicKeyType::KeyA).unwrap();
    // let block: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
    // acr122u_card
    //     .write_block(sector.block(FourBlockOffset::B0), block)
    //     .unwrap();
    // let block = acr122u_card.read_block(sector.block(FourBlockOffset::B0));
    // println!("Block data: {:02X?}", block);
    // acr122u_card.blink();
    // acr122u_card.blink();
    // acr122u_card.blink();
}
