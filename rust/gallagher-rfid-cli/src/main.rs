use std::env;
use std::fs::File;
use std::io::Read;

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
use gallagher_rfid_core::mifare::desfire::crypto::aes_cbc_decrypt_in_place;
use gallagher_rfid_core::mifare::desfire::{
    AccessCondition, ApplicationId, ApplicationKeyType, Command, CommandCode, CommunicationMode,
    Desfire, FileId, FileSettings, FileSettingsDetails, FileType, FrameCodec, KeyNumber,
    KeySettings, RndA, SessionKey, Transport, WrappedFraming, U24,
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
    if let Err(error) = card.reset_card() {
        eprintln!("Warning: card reset failed: {error}");
    }
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
            let desfire_args = match parse_desfire_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("desfire: {error}");
                    eprintln!(
                        "Usage: {} desfire [--aid <hex>] [--auth-aes <key_number>:<32_hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            read_desfire_tag(card, &desfire_args);
        }
        _ => {
            eprintln!("Usage: {} [read|write|desfire]", args[0]);
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DesfireArgs {
    aid_filter: Option<ApplicationId>,
    auth: Option<AesAuthSpec>,
    debug_read: bool,
}

#[derive(Debug, Clone, Copy)]
struct AesAuthSpec {
    key_number: KeyNumber,
    key: [u8; 16],
}

fn parse_desfire_args(args: &[String]) -> Result<DesfireArgs, String> {
    let mut aid_filter: Option<ApplicationId> = None;
    let mut auth: Option<AesAuthSpec> = None;
    let mut debug_read = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--aid" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--aid requires a hex value".to_string())?;
                aid_filter = Some(parse_aid(value)?);
            }
            "--auth-aes" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--auth-aes requires <key_number>:<32_hex>".to_string())?;
                auth = Some(parse_aes_auth_spec(value)?);
            }
            "--debug-read" => {
                debug_read = true;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(DesfireArgs {
        aid_filter,
        auth,
        debug_read,
    })
}

fn parse_aid(value: &str) -> Result<ApplicationId, String> {
    if value.is_empty() || value.len() > 6 {
        return Err(format!("--aid expects 1..=6 hex chars, got: {value}"));
    }
    let raw =
        u32::from_str_radix(value, 16).map_err(|error| format!("--aid invalid hex: {error}"))?;
    ApplicationId::new(raw).map_err(|error| format!("--aid out of range: {error:?}"))
}

fn parse_aes_auth_spec(value: &str) -> Result<AesAuthSpec, String> {
    let (number_str, key_str) = value
        .split_once(':')
        .ok_or_else(|| "--auth-aes expects <key_number>:<32_hex>".to_string())?;
    let key_number_value: u8 = number_str
        .parse()
        .map_err(|error| format!("--auth-aes key number: {error}"))?;
    let key_number = KeyNumber::new(key_number_value)
        .map_err(|error| format!("--auth-aes invalid key number: {error:?}"))?;
    let key_bytes =
        parse_hex(key_str).ok_or_else(|| format!("--auth-aes invalid hex key: {key_str}"))?;
    let key: [u8; 16] = key_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "--auth-aes expects 16-byte key (32 hex chars), got {} bytes",
            key_bytes.len()
        )
    })?;
    Ok(AesAuthSpec { key_number, key })
}

fn parse_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn random_rnd_a() -> std::io::Result<RndA> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(RndA::new(bytes))
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

fn read_desfire_tag<T: Transport>(transport: T, args: &DesfireArgs) {
    let mut desfire = Desfire::new(transport, WrappedFraming);

    // Abort any in-progress AF sequence from a previous run without card removal.
    // SELECT_APPLICATION(PICC) causes the card to discard pending multi-frame state and auth.
    let _ = desfire.select_application(ApplicationId::PICC);

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
    if let Err(error) = desfire.get_application_ids(&mut application_ids) {
        eprintln!("  GetApplicationIDs failed: {error:?}");
        return;
    }

    println!("\n=== Applications ===");
    if application_ids.is_empty() {
        println!("  No applications found.");
    } else {
        for application_id in &application_ids {
            println!("  AID 0x{:06X}", application_id.as_u32());
        }
    }

    let targets: Vec<ApplicationId> = match args.aid_filter {
        Some(filter) => {
            if !application_ids.contains(&filter) {
                println!(
                    "  Note: AID 0x{:06X} not in tag's application list (selecting anyway).",
                    filter.as_u32()
                );
            }
            vec![filter]
        }
        None => application_ids.iter().copied().collect(),
    };

    for application_id in targets {
        process_application(&mut desfire, application_id, args);
    }
}

fn process_application<T: Transport, C: FrameCodec>(
    desfire: &mut Desfire<T, C>,
    application_id: ApplicationId,
    args: &DesfireArgs,
) {
    println!("\n=== Application 0x{:06X} ===", application_id.as_u32());
    if let Err(error) = desfire.select_application(application_id) {
        eprintln!("  SelectApplication failed: {error:?}");
        return;
    }

    match desfire.get_key_settings() {
        Ok(settings) => {
            print_key_settings(settings);
            print_key_versions(desfire, settings);
        }
        Err(error) => eprintln!("  GetKeySettings failed: {error:?}"),
    }

    let mut file_ids: HeaplessVec<FileId, 32> = HeaplessVec::new();
    match desfire.get_file_ids(&mut file_ids) {
        Ok(()) if file_ids.is_empty() => {
            println!("  No files found.");
            return;
        }
        Ok(()) => {}
        Err(error) => {
            eprintln!("  GetFileIDs failed: {error:?}");
            return;
        }
    }

    let mut file_settings: Vec<(FileId, Option<FileSettings>)> = Vec::new();
    for file_id in &file_ids {
        println!("  File {}", file_id.as_byte());
        match desfire.get_file_settings(*file_id) {
            Ok(settings) => {
                print_file_settings(settings);
                maybe_read_plain_free_file(desfire, *file_id, settings);
                file_settings.push((*file_id, Some(settings)));
            }
            Err(error) => {
                eprintln!("    GetFileSettings failed: {error:?}");
                file_settings.push((*file_id, None));
            }
        }
    }

    if let Some(auth_spec) = args.auth {
        run_aes_auth_pass(desfire, application_id, auth_spec, &file_settings, args);
    }
}

fn run_aes_auth_pass<T: Transport, C: FrameCodec>(
    desfire: &mut Desfire<T, C>,
    application_id: ApplicationId,
    auth_spec: AesAuthSpec,
    file_settings: &[(FileId, Option<FileSettings>)],
    args: &DesfireArgs,
) {
    println!(
        "\n  --- AES auth (key {}, AID 0x{:06X}) ---",
        auth_spec.key_number.as_byte(),
        application_id.as_u32()
    );
    if let Err(error) = desfire.select_application(application_id) {
        eprintln!("    SelectApplication failed: {error:?}");
        return;
    }
    let rnd_a = match random_rnd_a() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("    /dev/urandom failed: {error}");
            return;
        }
    };
    if let Err(error) =
        desfire.authenticate_aes_with_rnd_a(auth_spec.key_number, &auth_spec.key, rnd_a)
    {
        eprintln!("    AuthenticateAES failed: {error:?}");
        return;
    }
    println!("    Authenticated.");

    for (file_id, settings) in file_settings {
        let Some(settings) = settings else { continue };
        let mode = settings.communication_mode();
        if !matches!(
            mode,
            CommunicationMode::Maced | CommunicationMode::Enciphered
        ) {
            continue;
        }
        let FileSettingsDetails::Data { size } = settings.details() else {
            continue;
        };
        if size.as_u32() == 0 {
            println!("    File {}: empty", file_id.as_byte());
            continue;
        }
        if size.as_u32() > 256 {
            println!(
                "    File {}: skipped ({} bytes is larger than CLI preview limit)",
                file_id.as_byte(),
                size.as_u32()
            );
            continue;
        }

        let mut data: HeaplessVec<u8, 256> = HeaplessVec::new();
        let offset = U24::new(0).unwrap();
        match mode {
            CommunicationMode::Maced => {
                match desfire.read_data_maced(*file_id, offset, size, &mut data) {
                    Ok(()) => println!(
                        "    File {} (maced): {:02X?}",
                        file_id.as_byte(),
                        data.as_slice()
                    ),
                    Err(error) => eprintln!(
                        "    File {} ReadDataMaced failed: {error:?}",
                        file_id.as_byte()
                    ),
                }
            }
            CommunicationMode::Enciphered => {
                match desfire.read_data_enciphered(*file_id, offset, size, &mut data) {
                    Ok(()) => println!(
                        "    File {} (encrypted): {:02X?}",
                        file_id.as_byte(),
                        data.as_slice()
                    ),
                    Err(error) => eprintln!(
                        "    File {} ReadDataEnciphered failed: {error:?}",
                        file_id.as_byte()
                    ),
                }
                if args.debug_read {
                    debug_encrypted_read(desfire, *file_id, size);
                }
            }
            CommunicationMode::Plain => unreachable!(),
        }
    }
}

fn debug_encrypted_read<T: Transport, C: FrameCodec>(
    desfire: &mut Desfire<T, C>,
    file_id: FileId,
    length: U24,
) {
    println!(
        "    --- debug raw read (file {}, length=0x{:06X}) ---",
        file_id.as_byte(),
        length.as_u32()
    );

    let Some(mut session) = desfire.authenticated_session() else {
        eprintln!("      not authenticated");
        return;
    };
    let SessionKey::Aes(session_key) = session.session_key();
    let pre_iv = session.cmac_chaining().state();

    let mut cmd_data: HeaplessVec<u8, 7> = HeaplessVec::new();
    if cmd_data.push(file_id.as_byte()).is_err()
        || cmd_data
            .extend_from_slice(&U24::new(0).unwrap().to_le_bytes())
            .is_err()
        || cmd_data.extend_from_slice(&length.to_le_bytes()).is_err()
    {
        eprintln!("      command buffer overflow");
        return;
    }

    let command = match Command::new(CommandCode::READ_DATA, cmd_data.as_slice()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("      Command::new failed: {error:?}");
            return;
        }
    };

    if let Err(error) = session.update_command_cmac(command.code(), command.data()) {
        eprintln!("      update_command_cmac failed: {error:?}");
        return;
    }
    let post_iv = session.cmac_chaining().state();

    println!("      cmd_code:    0x{:02X}", command.code().as_byte());
    println!("      cmd_data:    {:02X?}", command.data());
    println!("      pre_iv:      {pre_iv:02X?}");
    println!("      post_iv:     {post_iv:02X?}");
    println!("      session_key: {:02X?}", session_key.as_bytes());

    let response = match desfire.executor_mut().exchange_one(&command) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("      exchange_one failed: {error:?}");
            return;
        }
    };

    println!("      status:      0x{:02X}", response.status().as_byte());
    println!(
        "      encrypted ({} bytes): {:02X?}",
        response.data().len(),
        response.data()
    );

    if response.data().is_empty() || !response.data().len().is_multiple_of(16) {
        eprintln!("      response not 16-aligned, skipping decrypt");
        return;
    }

    let mut decrypted: HeaplessVec<u8, 256> = HeaplessVec::new();
    if decrypted.extend_from_slice(response.data()).is_err() {
        eprintln!("      response too large for debug buffer");
        return;
    }
    aes_cbc_decrypt_in_place(&session_key.as_bytes(), &post_iv, decrypted.as_mut_slice());
    println!(
        "      decrypted ({} bytes): {:02X?}",
        decrypted.len(),
        decrypted.as_slice()
    );
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

fn print_key_versions<T: Transport, C: FrameCodec>(
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

fn maybe_read_plain_free_file<T: Transport, C: FrameCodec>(
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
