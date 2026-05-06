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
use gallagher_rfid_core::mifare::desfire::{
    AccessCondition, ApplicationId, ApplicationKeyType, CommunicationMode, Desfire, FileId,
    FileSettings, FileSettingsDetails, FileType, KeyNumber, KeySettings, Transport, WrappedFraming,
    U24,
};
use gallagher_rfid_pcsc::{
    acr122u::Acr122uReader,
    smart_card::{SmartCardContext, SmartCardReader},
};
use heapless::Vec as HeaplessVec;

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
        "desfire" => {
            read_desfire_tag(card);
        }
        _ => {
            eprintln!("Usage: {} [read|write|desfire]", args[0]);
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

fn read_desfire_tag<T: Transport>(transport: T) {
    let mut desfire = Desfire::new(transport, WrappedFraming);

    println!("=== DESFire ===");
    match desfire.get_version() {
        Ok(version) => {
            println!("  UID:              {:02X?}", version.uid());
            println!(
                "  Hardware:         vendor=0x{:02X} type=0x{:02X} subtype=0x{:02X} v{}.{} storage=0x{:02X} protocol=0x{:02X}",
                version.hardware().vendor_id(),
                version.hardware().card_type(),
                version.hardware().subtype(),
                version.hardware().major_decimal(),
                version.hardware().minor_decimal(),
                version.hardware().storage_size(),
                version.hardware().protocol(),
            );
            println!(
                "  Software:         vendor=0x{:02X} type=0x{:02X} subtype=0x{:02X} v{}.{} storage=0x{:02X} protocol=0x{:02X}",
                version.software().vendor_id(),
                version.software().card_type(),
                version.software().subtype(),
                version.software().major_decimal(),
                version.software().minor_decimal(),
                version.software().storage_size(),
                version.software().protocol(),
            );
            println!("  Batch:            {:02X?}", version.batch_number());
            println!(
                "  Production:       week={} year=20{:02}",
                version.production_week_decimal(),
                version.production_year_decimal()
            );
        }
        Err(error) => {
            eprintln!("  GetVersion failed: {error:?}");
            return;
        }
    }

    println!("\n=== PICC ===");
    match desfire.get_key_settings() {
        Ok(settings) => {
            print_key_settings(settings);
            print_key_versions(&mut desfire, settings);
        }
        Err(error) => eprintln!("  GetKeySettings failed: {error:?}"),
    }
    match desfire.free_memory() {
        Ok(memory) => println!("  Free memory:      {} bytes", memory.as_u32()),
        Err(error) => eprintln!("  FreeMem failed: {error:?}"),
    }

    let mut application_ids: HeaplessVec<ApplicationId, 32> = HeaplessVec::new();
    match desfire.get_application_ids(&mut application_ids) {
        Ok(()) => {
            if application_ids.is_empty() {
                println!("\n=== Applications ===");
                println!("  No applications found.");
                return;
            }

            println!("\n=== Applications ===");
            for application_id in &application_ids {
                println!("  AID 0x{:06X}", application_id.as_u32());
            }
        }
        Err(error) => {
            eprintln!("  GetApplicationIDs failed: {error:?}");
            return;
        }
    }

    for application_id in application_ids {
        println!("\n=== Application 0x{:06X} ===", application_id.as_u32());
        if let Err(error) = desfire.select_application(application_id) {
            eprintln!("  SelectApplication failed: {error:?}");
            continue;
        }

        match desfire.get_key_settings() {
            Ok(settings) => {
                print_key_settings(settings);
                print_key_versions(&mut desfire, settings);
            }
            Err(error) => eprintln!("  GetKeySettings failed: {error:?}"),
        }

        let mut file_ids: HeaplessVec<FileId, 32> = HeaplessVec::new();
        match desfire.get_file_ids(&mut file_ids) {
            Ok(()) if file_ids.is_empty() => {
                println!("  No files found.");
                continue;
            }
            Ok(()) => {}
            Err(error) => {
                eprintln!("  GetFileIDs failed: {error:?}");
                continue;
            }
        }

        for file_id in file_ids {
            println!("  File {}", file_id.as_byte());
            match desfire.get_file_settings(file_id) {
                Ok(settings) => {
                    print_file_settings(settings);
                    maybe_read_plain_free_file(&mut desfire, file_id, settings);
                }
                Err(error) => eprintln!("    GetFileSettings failed: {error:?}"),
            }
        }
    }
}

fn print_key_settings(settings: KeySettings) {
    println!(
        "  Key settings raw: {:02X} {:02X}",
        settings.raw_settings(),
        settings.raw_key_count()
    );
    println!("  Key count:        {}", settings.key_count());
    println!(
        "  Key type:         {}",
        application_key_type_name(settings.key_type())
    );
    println!(
        "  Rights:           cfg_changeable={} create_delete_requires_mk={} list_requires_mk={} mk_changeable={}",
        settings.configuration_changeable(),
        settings.master_key_required_for_create_delete(),
        settings.master_key_required_for_list(),
        settings.master_key_changeable(),
    );
}

fn print_key_versions<T: Transport, C: gallagher_rfid_core::mifare::desfire::FrameCodec>(
    desfire: &mut Desfire<T, C>,
    settings: KeySettings,
) {
    for key_number in 0..settings.key_count() {
        let Ok(key_number) = KeyNumber::new(key_number) else {
            continue;
        };
        match desfire.get_key_version(key_number) {
            Ok(version) => println!(
                "  Key {} version:   {} (0x{version:02X})",
                key_number.as_byte(),
                version
            ),
            Err(error) => eprintln!(
                "  GetKeyVersion({}) failed: {error:?}",
                key_number.as_byte()
            ),
        }
    }
}

fn print_file_settings(settings: FileSettings) {
    println!(
        "    Type:           {}",
        file_type_name(settings.file_type())
    );
    println!(
        "    Communication:  {}",
        communication_mode_name(settings.communication_mode())
    );
    println!(
        "    Access:         read={} write={} read_write={} change={}",
        access_condition_name(settings.access_rights().read()),
        access_condition_name(settings.access_rights().write()),
        access_condition_name(settings.access_rights().read_write()),
        access_condition_name(settings.access_rights().change()),
    );

    match settings.details() {
        FileSettingsDetails::Data { size } => {
            println!("    Size:           {} bytes", size.as_u32());
        }
        FileSettingsDetails::Value {
            lower_limit,
            upper_limit,
            limited_credit_value,
            limited_credit_enabled,
        } => {
            println!("    Lower limit:    {lower_limit}");
            println!("    Upper limit:    {upper_limit}");
            println!("    Limited credit: {limited_credit_value}");
            println!("    Credit enabled: {limited_credit_enabled}");
        }
        FileSettingsDetails::Record {
            record_size,
            max_records,
            current_records,
        } => {
            println!("    Record size:    {} bytes", record_size.as_u32());
            println!("    Max records:    {}", max_records.as_u32());
            println!("    Records:        {}", current_records.as_u32());
        }
    }
}

fn maybe_read_plain_free_file<T: Transport, C: gallagher_rfid_core::mifare::desfire::FrameCodec>(
    desfire: &mut Desfire<T, C>,
    file_id: FileId,
    settings: FileSettings,
) {
    let FileSettingsDetails::Data { size } = settings.details() else {
        return;
    };

    if settings.communication_mode() != CommunicationMode::Plain {
        println!("    Data:           skipped (not plain communication)");
        return;
    }

    if !is_free_read(settings) {
        println!("    Data:           skipped (read requires authentication)");
        return;
    }

    if size.as_u32() == 0 {
        println!("    Data:           empty");
        return;
    }

    if size.as_u32() > 128 {
        println!(
            "    Data:           skipped ({} bytes is larger than CLI preview limit)",
            size.as_u32()
        );
        return;
    }

    let mut data: HeaplessVec<u8, 128> = HeaplessVec::new();
    match desfire.read_data(file_id, U24::new(0).unwrap(), size, &mut data) {
        Ok(()) => println!("    Data:           {:02X?}", data.as_slice()),
        Err(error) => eprintln!("    ReadData failed: {error:?}"),
    }
}

fn is_free_read(settings: FileSettings) -> bool {
    matches!(settings.access_rights().read(), AccessCondition::Free)
        || matches!(settings.access_rights().read_write(), AccessCondition::Free)
}

fn file_type_name(file_type: FileType) -> &'static str {
    match file_type {
        FileType::StandardData => "standard data",
        FileType::BackupData => "backup data",
        FileType::Value => "value",
        FileType::LinearRecord => "linear record",
        FileType::CyclicRecord => "cyclic record",
    }
}

fn communication_mode_name(mode: CommunicationMode) -> &'static str {
    match mode {
        CommunicationMode::Plain => "plain",
        CommunicationMode::Maced => "MACed",
        CommunicationMode::Enciphered => "enciphered",
    }
}

fn application_key_type_name(key_type: ApplicationKeyType) -> &'static str {
    match key_type {
        ApplicationKeyType::TwoKey3Des => "2TDEA",
        ApplicationKeyType::ThreeKey3Des => "3TDEA",
        ApplicationKeyType::Aes => "AES",
        ApplicationKeyType::Rfu => "RFU",
    }
}

fn access_condition_name(condition: AccessCondition) -> String {
    match condition {
        AccessCondition::Key(key) => format!("key {}", key.as_byte()),
        AccessCondition::Free => "free".to_string(),
        AccessCondition::Never => "never".to_string(),
    }
}
