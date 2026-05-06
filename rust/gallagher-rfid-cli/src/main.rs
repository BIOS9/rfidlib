use std::env;

use gallagher_rfid_core::gallagher::credential::GallagherCredential;
use gallagher_rfid_core::gallagher::mifare_classic::cad::CardApplicationDirectory;
use gallagher_rfid_core::gallagher::mifare_classic::{
    write_credential_to_sector, GallagherMifareClassic, CAD_AID, CREDENTIAL_AID, CREDENTIAL_KEY_A,
    CREDENTIAL_KEY_B,
};
use gallagher_rfid_core::mifare::application_directory::{
    MadAid, MadVersion, MifareApplicationDirectory, NonMadSector,
};
use gallagher_rfid_core::mifare::classic::{FourBlockSector, KeyProvider, KeyType, Sector, Tag};
use gallagher_rfid_pcsc::{
    acr122u::Acr122uReader,
    smart_card::{SmartCardContext, SmartCardReader},
};

const CAD_SECTOR: FourBlockSector = FourBlockSector::S14;
const CREDENTIAL_SECTOR: FourBlockSector = FourBlockSector::S15;

struct ReadKeyProvider;
impl KeyProvider for ReadKeyProvider {
    fn authenticate<T: Tag>(
        &self,
        tag: &mut T,
        sector: gallagher_rfid_core::mifare::classic::Sector,
    ) -> Result<(), gallagher_rfid_core::mifare::classic::Error> {
        const KEYS: &[[u8; 6]] = &[
            CREDENTIAL_KEY_A,
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ];
        for key in KEYS {
            if tag.authenticate(sector, key, KeyType::KeyA).is_ok() {
                return Ok(());
            }
        }
        Err(gallagher_rfid_core::mifare::classic::Error::AuthenticationFailed(sector))
    }
}

struct WriteKeyProvider;
impl KeyProvider for WriteKeyProvider {
    fn authenticate<T: Tag>(
        &self,
        tag: &mut T,
        sector: gallagher_rfid_core::mifare::classic::Sector,
    ) -> Result<(), gallagher_rfid_core::mifare::classic::Error> {
        const KEYS: &[[u8; 6]] = &[
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
            CREDENTIAL_KEY_B,
        ];
        for key in KEYS {
            if tag.authenticate(sector, key, KeyType::KeyB).is_ok() {
                return Ok(());
            }
        }
        Err(gallagher_rfid_core::mifare::classic::Error::AuthenticationFailed(sector))
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map_or("read", String::as_str);

    let context = SmartCardContext::establish().unwrap();
    let readers: Vec<SmartCardReader> = context.get_readers().unwrap().collect();

    for reader in &readers {
        println!("Found reader: {}", reader.name);
    }

    let reader = readers
        .into_iter()
        .find(|r| r.name.starts_with("ACS ACR122"))
        .expect("Failed to find ACR122u");

    println!("Using reader: {}", reader.name);

    let acr122u = Acr122uReader::try_from(reader).unwrap();
    let mut card = acr122u.connect_to_card().unwrap();
    card.set_card_detect_beep(false).unwrap();

    match command {
        "read" => {
            read_gallagher_tag(&mut card);
        }
        "write" => {
            let credential = GallagherCredential::new(
                1,       // region code A
                123,     // facility code
                123_456, // card number
                1,       // issue level
            )
            .unwrap();
            write_gallagher_tag(&mut card, credential);
            println!("Write complete.");
        }
        _ => {
            eprintln!("Usage: {} [read|write]", args[0]);
            std::process::exit(1);
        }
    }
}

fn read_gallagher_tag<T: Tag>(tag: &mut T) {
    // --- MAD ---
    let mad = match MifareApplicationDirectory::read_from_tag(tag, &ReadKeyProvider) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("MAD read failed: {e:?}");
            return;
        }
    };

    println!("=== MAD ===");
    println!("  Version:          {:?}", mad.mad_version);
    println!("  Multi-app:        {}", mad.multi_application_card);
    match mad.card_publisher_sector {
        Some(s) => println!("  Publisher sector: {}", u8::from(s)),
        None => println!("  Publisher sector: none"),
    }
    println!("  Applications:");
    for (sector, aid) in mad.iter_applications() {
        println!(
            "    Sector {:>2} -> AID 0x{:04X}",
            u8::from(sector),
            aid.to_u16()
        );
    }

    // --- CAD ---
    let cad_sector = mad
        .iter_applications()
        .find(|(_, aid)| aid.to_u16() == CAD_AID)
        .and_then(|(s, _)| match Sector::from(s) {
            Sector::FourBlock(fb) => Some(fb),
            Sector::SixteenBlock(_) => None,
        });

    println!("\n=== CAD ===");
    match cad_sector {
        None => println!("  No CAD sector in MAD."),
        Some(sector) => {
            match CardApplicationDirectory::read_from_tag(tag, sector, &ReadKeyProvider) {
                Ok(cad) => {
                    for ((rc, fc), cred_sector) in &cad.mappings {
                        println!("  RC {rc:>2} FC {fc:>5} -> sector {cred_sector}");
                    }
                }
                Err(e) => eprintln!("  CAD read failed: {e:?}"),
            }
        }
    }

    // --- Credentials ---
    println!("\n=== Credentials ===");
    match GallagherMifareClassic::read_from_tag(tag, &ReadKeyProvider) {
        Ok(result) => {
            if result.credentials.is_empty() {
                println!("  No credentials found.");
            }
            for (sector, cred) in &result.credentials {
                println!(
                    "  Sector {:>2} | Region {} ({}) | Facility {:>5} | Card {:>8} | Issue {}",
                    u8::from(*sector),
                    cred.region_code,
                    cred.region_code_letter(),
                    cred.facility_code,
                    cred.card_number,
                    cred.issue_level,
                );
            }
        }
        Err(e) => eprintln!("  Credential read failed: {e:?}"),
    }
}

fn write_gallagher_tag<T: Tag>(tag: &mut T, credential: GallagherCredential) {
    let cad_non_mad = NonMadSector::try_from(Sector::from(CAD_SECTOR)).unwrap();
    let cred_non_mad = NonMadSector::try_from(Sector::from(CREDENTIAL_SECTOR)).unwrap();

    println!(
        "Writing credential to sector {}...",
        CREDENTIAL_SECTOR as u8
    );
    write_credential_to_sector(
        tag,
        CREDENTIAL_SECTOR,
        &credential,
        &WriteKeyProvider,
        &CREDENTIAL_KEY_A,
        &CREDENTIAL_KEY_B,
    )
    .unwrap();

    println!("Writing CAD to sector {}...", CAD_SECTOR as u8);
    let cad = CardApplicationDirectory::new([(
        (credential.region_code, credential.facility_code),
        CREDENTIAL_SECTOR as u8,
    )]);
    cad.write_to_tag(tag, CAD_SECTOR, &WriteKeyProvider)
        .unwrap();

    println!("Writing MAD to sector 0...");
    let mad = MifareApplicationDirectory::new(
        true,
        MadVersion::V1,
        None,
        [
            (cad_non_mad, MadAid::try_from_u16(CAD_AID).unwrap()),
            (cred_non_mad, MadAid::try_from_u16(CREDENTIAL_AID).unwrap()),
        ],
    )
    .unwrap();
    mad.write_to_tag(tag, &WriteKeyProvider).unwrap();
}
