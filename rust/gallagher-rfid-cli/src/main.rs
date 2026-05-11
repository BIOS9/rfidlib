use std::env;
use std::fs::File;
use std::io::Read;

mod desfire_integration;

use gallagher_rfid_core::gallagher::credential::GallagherCredential;
use gallagher_rfid_core::gallagher::desfire::{GallagherDesfireKeySource, GallagherDesfireReader};
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
    AccessCondition, AccessRights, ApplicationId, ApplicationKeyType, Command, CommandCode,
    CommunicationMode, Desfire, FileId, FileSettings, FileSettingsDetails, FileType, FrameCodec,
    KeyNumber, KeySettings, RndA, RndA8, Transport, WrappedFraming, U24,
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
            let read_args = match parse_read_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("read: {error}");
                    eprintln!("Usage: {} read [--desfire] [--sitekey <32_hex>]", args[0]);
                    return;
                }
            };
            read_gallagher_tag(&mut card, &read_args);
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
                        "Usage: {} desfire [--aid <hex>] [--auth-aes <n>:<32_hex>] [--auth-des <n>:<16_hex>] [--auth-2tdea <n>:<32_hex>] [--auth-3tdea <n>:<48_hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            read_desfire_tag(card, &desfire_args);
        }
        "desfire-integration" | "desfire-itest" => {
            let integration_args = match desfire_integration::parse_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("desfire-integration: {error}");
                    eprintln!(
                        "Usage: {} desfire-integration [--yes] [--skip-format] [--picc-auth-aes <n>:<32_hex> | --picc-auth-2tdea <n>:<32_hex> | --picc-auth-3tdea <n>:<48_hex> | --picc-auth-des <n>:<16_hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            if !desfire_integration::run(card, integration_args) {
                std::process::exit(1);
            }
        }
        "desfire-format" => {
            let auth = match parse_optional_aes_auth(&args[2..]) {
                Ok(a) => a,
                Err(error) => {
                    eprintln!("desfire-format: {error}");
                    eprintln!(
                        "Usage: {} desfire-format [--auth-aes <n>:<32_hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            format_desfire(card, auth);
        }
        "desfire-provision" => {
            let provision_args = match parse_provision_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("desfire-provision: {error}");
                    eprintln!(
                        "Usage: {} desfire-provision --aid <hex> [--picc-auth-aes <n>:<32_hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            provision_desfire(card, &provision_args);
        }
        "desfire-changekey" => {
            let ck_args = match parse_change_key_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("desfire-changekey: {error}");
                    eprintln!(
                        "Usage: {} desfire-changekey [--aid <hex>] --auth-aes <n>:<32hex> \
                         (--picc | --newkeyno <n>) --newkey <32hex> [--newver <v>] [--oldkey <32hex>]",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            change_key_desfire(card, &ck_args);
        }
        "desfire-delete" => {
            let delete_args = match parse_delete_args(&args[2..]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("desfire-delete: {error}");
                    eprintln!(
                        "Usage: {} desfire-delete --aid <hex> [--auth-aes <n>:<32_hex>] [--file <id>]...",
                        args[0]
                    );
                    std::process::exit(1);
                }
            };
            delete_desfire(card, &delete_args);
        }
        _ => {
            eprintln!("Usage: {} [read|write|desfire|desfire-integration|desfire-format|desfire-provision|desfire-delete|desfire-changekey]", args[0]);
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DesfireArgs {
    aid_filter: Option<ApplicationId>,
    auth: Option<DesfireAuthSpec>,
    debug_read: bool,
    write: bool,
}

#[derive(Debug, Clone, Copy)]
enum DesfireAuthSpec {
    Aes(AesAuthSpec),
    Des(DesAuthSpec),
    Tdea2(Tdea2AuthSpec),
    Tdea3(Tdea3AuthSpec),
}

impl DesfireAuthSpec {
    const fn key_number(self) -> KeyNumber {
        match self {
            Self::Aes(spec) => spec.key_number,
            Self::Des(spec) => spec.key_number,
            Self::Tdea2(spec) => spec.key_number,
            Self::Tdea3(spec) => spec.key_number,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Aes(_) => "AES",
            Self::Des(_) => "DES",
            Self::Tdea2(_) => "2TDEA",
            Self::Tdea3(_) => "3TDEA",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AesAuthSpec {
    key_number: KeyNumber,
    key: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
struct DesAuthSpec {
    key_number: KeyNumber,
    key: [u8; 8],
}

#[derive(Debug, Clone, Copy)]
struct Tdea2AuthSpec {
    key_number: KeyNumber,
    key: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
struct Tdea3AuthSpec {
    key_number: KeyNumber,
    key: [u8; 24],
}

fn parse_desfire_args(args: &[String]) -> Result<DesfireArgs, String> {
    let mut aid_filter: Option<ApplicationId> = None;
    let mut auth: Option<DesfireAuthSpec> = None;
    let mut debug_read = false;
    let mut write = false;
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
                set_desfire_auth(&mut auth, DesfireAuthSpec::Aes(parse_aes_auth_spec(value)?))?;
            }
            "--auth-des" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--auth-des requires <key_number>:<16_hex>".to_string())?;
                set_desfire_auth(&mut auth, DesfireAuthSpec::Des(parse_des_auth_spec(value)?))?;
            }
            "--auth-2tdea" | "--auth-2k3des" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--auth-2tdea requires <key_number>:<32_hex>".to_string())?;
                set_desfire_auth(
                    &mut auth,
                    DesfireAuthSpec::Tdea2(parse_tdea2_auth_spec(value)?),
                )?;
            }
            "--auth-3tdea" | "--auth-3k3des" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--auth-3tdea requires <key_number>:<48_hex>".to_string())?;
                set_desfire_auth(
                    &mut auth,
                    DesfireAuthSpec::Tdea3(parse_tdea3_auth_spec(value)?),
                )?;
            }
            "--debug-read" => {
                debug_read = true;
            }
            "--write" => {
                write = true;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(DesfireArgs {
        aid_filter,
        auth,
        debug_read,
        write,
    })
}

struct ProvisionArgs {
    aid: ApplicationId,
    picc_auth: Option<AesAuthSpec>,
}

struct DeleteArgs {
    aid: ApplicationId,
    auth: Option<AesAuthSpec>,
    files: Vec<FileId>,
}

fn parse_provision_args(args: &[String]) -> Result<ProvisionArgs, String> {
    let mut aid: Option<ApplicationId> = None;
    let mut picc_auth: Option<AesAuthSpec> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--aid" => {
                let v = iter.next().ok_or("--aid requires a hex value")?;
                aid = Some(parse_aid(v)?);
            }
            "--picc-auth-aes" => {
                let v = iter.next().ok_or("--picc-auth-aes requires <n>:<32_hex>")?;
                picc_auth = Some(parse_aes_auth_spec(v)?);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(ProvisionArgs {
        aid: aid.ok_or("--aid is required")?,
        picc_auth,
    })
}

fn parse_delete_args(args: &[String]) -> Result<DeleteArgs, String> {
    let mut aid: Option<ApplicationId> = None;
    let mut auth: Option<AesAuthSpec> = None;
    let mut files: Vec<FileId> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--aid" => {
                let v = iter.next().ok_or("--aid requires a hex value")?;
                aid = Some(parse_aid(v)?);
            }
            "--auth-aes" => {
                let v = iter.next().ok_or("--auth-aes requires <n>:<32_hex>")?;
                auth = Some(parse_aes_auth_spec(v)?);
            }
            "--file" => {
                let v = iter.next().ok_or("--file requires an id (0-31)")?;
                let raw: u8 = v.parse().map_err(|e| format!("--file invalid id: {e}"))?;
                files.push(FileId::new(raw).map_err(|e| format!("--file out of range: {e:?}"))?);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(DeleteArgs {
        aid: aid.ok_or("--aid is required")?,
        auth,
        files,
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
    let (key_number, key) = parse_keyed_hex_spec(value, "--auth-aes")?;
    Ok(AesAuthSpec { key_number, key })
}

fn parse_des_auth_spec(value: &str) -> Result<DesAuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--auth-des")?;
    Ok(DesAuthSpec { key_number, key })
}

fn parse_tdea2_auth_spec(value: &str) -> Result<Tdea2AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--auth-2tdea")?;
    Ok(Tdea2AuthSpec { key_number, key })
}

fn parse_tdea3_auth_spec(value: &str) -> Result<Tdea3AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--auth-3tdea")?;
    Ok(Tdea3AuthSpec { key_number, key })
}

fn parse_keyed_hex_spec<const N: usize>(
    value: &str,
    option: &str,
) -> Result<(KeyNumber, [u8; N]), String> {
    let (number_str, key_str) = value
        .split_once(':')
        .ok_or_else(|| format!("{option} expects <key_number>:<hex_key>"))?;
    let key_number_value: u8 = number_str
        .parse()
        .map_err(|error| format!("{option} key number: {error}"))?;
    let key_number = KeyNumber::new(key_number_value)
        .map_err(|error| format!("{option} invalid key number: {error:?}"))?;
    let key_bytes =
        parse_hex(key_str).ok_or_else(|| format!("{option} invalid hex key: {key_str}"))?;
    let key: [u8; N] = key_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{option} expects {}-byte key ({} hex chars), got {} bytes",
            N,
            N * 2,
            key_bytes.len(),
        )
    })?;
    Ok((key_number, key))
}

fn set_desfire_auth(
    auth: &mut Option<DesfireAuthSpec>,
    value: DesfireAuthSpec,
) -> Result<(), String> {
    if auth.replace(value).is_some() {
        return Err("only one DESFire auth option may be supplied".to_string());
    }
    Ok(())
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

fn random_rnd_a8() -> std::io::Result<RndA8> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(RndA8::new(bytes))
}

fn random_bytes(len: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct ReadArgs {
    desfire_only: bool,
    desfire_key_source: GallagherDesfireKeySource,
}

fn parse_read_args(args: &[String]) -> Result<ReadArgs, String> {
    let mut desfire_only = false;
    let mut desfire_key_source = GallagherDesfireKeySource::DefaultSiteKey;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--desfire" => desfire_only = true,
            "--sitekey" => {
                let value = iter.next().ok_or("--sitekey requires 32 hex chars")?;
                let bytes =
                    parse_hex(value).ok_or_else(|| format!("--sitekey invalid hex: {value}"))?;
                let key: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "--sitekey must be 16 bytes (32 hex chars), got {}",
                        bytes.len()
                    )
                })?;
                desfire_key_source = GallagherDesfireKeySource::SiteKey(key);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    Ok(ReadArgs {
        desfire_only,
        desfire_key_source,
    })
}

fn parse_optional_aes_auth(args: &[String]) -> Result<Option<AesAuthSpec>, String> {
    let mut auth: Option<AesAuthSpec> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--auth-aes" => {
                let v = iter.next().ok_or("--auth-aes requires <n>:<32_hex>")?;
                auth = Some(parse_aes_auth_spec(v)?);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(auth)
}

struct ChangeKeyArgs {
    aid: ApplicationId,
    auth: AesAuthSpec,
    picc: bool,
    new_key_number: KeyNumber,
    new_key: [u8; 16],
    new_key_version: u8,
    old_key: Option<[u8; 16]>,
}

fn parse_change_key_args(args: &[String]) -> Result<ChangeKeyArgs, String> {
    let mut aid: Option<ApplicationId> = None;
    let mut auth: Option<AesAuthSpec> = None;
    let mut picc = false;
    let mut new_key_number: Option<KeyNumber> = None;
    let mut new_key: Option<[u8; 16]> = None;
    let mut new_key_version: u8 = 0;
    let mut old_key: Option<[u8; 16]> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--aid" => {
                let v = iter.next().ok_or("--aid requires a hex value")?;
                aid = Some(parse_aid(v)?);
            }
            "--auth-aes" => {
                let v = iter.next().ok_or("--auth-aes requires <n>:<32hex>")?;
                auth = Some(parse_aes_auth_spec(v)?);
            }
            "--picc" => {
                picc = true;
            }
            "--newkeyno" => {
                let v = iter.next().ok_or("--newkeyno requires a number 0-13")?;
                let raw: u8 = v.parse().map_err(|e| format!("--newkeyno: {e}"))?;
                new_key_number = Some(
                    KeyNumber::new(raw).map_err(|e| format!("--newkeyno out of range: {e:?}"))?,
                );
            }
            "--newkey" => {
                let v = iter.next().ok_or("--newkey requires 32 hex chars")?;
                let bytes = parse_hex(v).ok_or_else(|| format!("--newkey invalid hex: {v}"))?;
                new_key = Some(bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "--newkey must be 16 bytes (32 hex chars), got {}",
                        bytes.len()
                    )
                })?);
            }
            "--newver" => {
                let v = iter.next().ok_or("--newver requires a number 0-255")?;
                new_key_version = v.parse().map_err(|e| format!("--newver: {e}"))?;
            }
            "--oldkey" => {
                let v = iter.next().ok_or("--oldkey requires 32 hex chars")?;
                let bytes = parse_hex(v).ok_or_else(|| format!("--oldkey invalid hex: {v}"))?;
                old_key = Some(bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "--oldkey must be 16 bytes (32 hex chars), got {}",
                        bytes.len()
                    )
                })?);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if picc && new_key_number.is_some() {
        return Err("--picc and --newkeyno are mutually exclusive".to_string());
    }
    if !picc && new_key_number.is_none() {
        return Err("one of --picc or --newkeyno is required".to_string());
    }
    let resolved_aid = if picc {
        aid.unwrap_or(ApplicationId::PICC)
    } else {
        aid.ok_or("--aid is required for app-level key change")?
    };
    Ok(ChangeKeyArgs {
        aid: resolved_aid,
        auth: auth.ok_or("--auth-aes is required")?,
        picc,
        new_key_number: new_key_number.unwrap_or(KeyNumber::new(0).unwrap()),
        new_key: new_key.ok_or("--newkey is required")?,
        new_key_version,
        old_key,
    })
}

fn change_key_desfire<T: Transport>(transport: T, args: &ChangeKeyArgs) {
    let mut desfire = Desfire::new(transport, WrappedFraming);
    if let Err(e) = desfire.select_application(args.aid) {
        eprintln!("  SelectApplication failed: {e:?}");
        return;
    }

    let rnd_a = match random_rnd_a() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  /dev/urandom: {e}");
            return;
        }
    };
    match desfire.authenticate_aes_with_rnd_a(args.auth.key_number, &args.auth.key, rnd_a) {
        Ok(session) => println!(
            "  Authenticated as key {} (session key: {:02X?}).",
            args.auth.key_number.as_byte(),
            session.session_key()
        ),
        Err(e) => {
            eprintln!("  Auth failed: {e:?}");
            return;
        }
    }

    let result = if args.picc {
        println!(
            "  Changing PICC master key (version 0x{:02X}) [session will be cleared]...",
            args.new_key_version
        );
        desfire.change_picc_key_aes(args.new_key, args.new_key_version)
    } else {
        let same_key = args.new_key_number == args.auth.key_number;
        if !same_key && args.old_key.is_none() {
            eprintln!(
                "  Changing key {} requires --oldkey (current value of that slot).",
                args.new_key_number.as_byte()
            );
            return;
        }
        println!(
            "  Changing key {} (version 0x{:02X}){}...",
            args.new_key_number.as_byte(),
            args.new_key_version,
            if same_key {
                " [same key as auth — session will be cleared]"
            } else {
                ""
            },
        );
        desfire.change_key_aes(
            args.new_key_number,
            args.new_key,
            args.new_key_version,
            args.old_key,
        )
    };

    match result {
        Ok(()) => println!("  Key changed successfully."),
        Err(e) => eprintln!("  ChangeKey failed: {e:?}"),
    }
}

fn format_desfire<T: Transport>(transport: T, auth: Option<AesAuthSpec>) {
    let mut desfire = Desfire::new(transport, WrappedFraming);
    let _ = desfire.select_application(ApplicationId::PICC);

    if let Some(auth) = auth {
        let rnd_a = match random_rnd_a() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  /dev/urandom: {e}");
                return;
            }
        };
        match desfire.authenticate_aes_with_rnd_a(auth.key_number, &auth.key, rnd_a) {
            Ok(_) => println!("  PICC authenticated."),
            Err(e) => {
                eprintln!("  PICC auth failed: {e:?}");
                return;
            }
        }
    }

    match desfire.format_picc() {
        Ok(()) => println!("  PICC formatted. All applications deleted, memory reclaimed."),
        Err(e) => eprintln!("  FormatPICC failed: {e:?}"),
    }
}

fn provision_desfire<T: Transport>(transport: T, args: &ProvisionArgs) {
    let mut desfire = Desfire::new(transport, WrappedFraming);
    let _ = desfire.select_application(ApplicationId::PICC);

    if let Some(auth) = args.picc_auth {
        let rnd_a = match random_rnd_a() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  /dev/urandom: {e}");
                return;
            }
        };
        match desfire.authenticate_aes_with_rnd_a(auth.key_number, &auth.key, rnd_a) {
            Ok(_) => println!("  PICC authenticated."),
            Err(e) => {
                eprintln!("  PICC auth failed: {e:?}");
                return;
            }
        }
    }

    let key_settings = KeySettings::new(0x0F, ApplicationKeyType::Aes, 3);
    match desfire.create_application(args.aid, key_settings) {
        Ok(()) => println!("  Created application 0x{:06X}.", args.aid.as_u32()),
        Err(e) => {
            eprintln!("  CreateApplication failed: {e:?}");
            return;
        }
    }

    if let Err(e) = desfire.select_application(args.aid) {
        eprintln!("  SelectApplication failed: {e:?}");
        return;
    }
    let rnd_a = match random_rnd_a() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  /dev/urandom: {e}");
            return;
        }
    };
    match desfire.authenticate_aes_with_rnd_a(KeyNumber::new(0).unwrap(), &[0u8; 16], rnd_a) {
        Ok(_) => println!("  App authenticated (default key)."),
        Err(e) => {
            eprintln!("  App auth failed: {e:?}");
            return;
        }
    }

    let key0 = AccessCondition::Key(KeyNumber::new(0).unwrap());
    let access = AccessRights::new(AccessCondition::Free, key0, key0, key0);
    let size32 = U24::new(32).unwrap();
    let size16 = U24::new(16).unwrap();
    let rec_size = U24::new(16).unwrap();
    let max_rec = U24::new(8).unwrap();

    for (id, mode, label) in [
        (0u8, CommunicationMode::Plain, "standard data, plain, 32 B"),
        (1u8, CommunicationMode::Maced, "standard data, MACed, 32 B"),
        (
            2u8,
            CommunicationMode::Enciphered,
            "standard data, enciphered, 32 B",
        ),
    ] {
        let fid = FileId::new(id).unwrap();
        match desfire.create_std_data_file(fid, mode, access, size32) {
            Ok(()) => println!("  File {id}: {label}."),
            Err(e) => eprintln!("  File {id} CreateStdDataFile failed: {e:?}"),
        }
    }

    match desfire.create_backup_data_file(
        FileId::new(3).unwrap(),
        CommunicationMode::Plain,
        access,
        size16,
    ) {
        Ok(()) => println!("  File 3: backup data, plain, 16 B."),
        Err(e) => eprintln!("  File 3 CreateBackupDataFile failed: {e:?}"),
    }

    match desfire.create_value_file(
        FileId::new(4).unwrap(),
        CommunicationMode::Plain,
        access,
        0,
        1000,
        0,
        false,
    ) {
        Ok(()) => println!("  File 4: value, plain, limits 0..1000, initial 0."),
        Err(e) => eprintln!("  File 4 CreateValueFile failed: {e:?}"),
    }

    match desfire.create_linear_record_file(
        FileId::new(5).unwrap(),
        CommunicationMode::Plain,
        access,
        rec_size,
        max_rec,
    ) {
        Ok(()) => println!("  File 5: linear record, plain, 16 B/record, 8 max."),
        Err(e) => eprintln!("  File 5 CreateLinearRecordFile failed: {e:?}"),
    }

    match desfire.create_cyclic_record_file(
        FileId::new(6).unwrap(),
        CommunicationMode::Plain,
        access,
        rec_size,
        max_rec,
    ) {
        Ok(()) => println!("  File 6: cyclic record, plain, 16 B/record, 8 max."),
        Err(e) => eprintln!("  File 6 CreateCyclicRecordFile failed: {e:?}"),
    }
}

fn delete_desfire<T: Transport>(transport: T, args: &DeleteArgs) {
    let mut desfire = Desfire::new(transport, WrappedFraming);
    let _ = desfire.select_application(ApplicationId::PICC);

    if args.files.is_empty() {
        // No files specified: delete the whole application (PICC-level auth).
        if let Some(auth) = args.auth {
            let rnd_a = match random_rnd_a() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  /dev/urandom: {e}");
                    return;
                }
            };
            match desfire.authenticate_aes_with_rnd_a(auth.key_number, &auth.key, rnd_a) {
                Ok(_) => println!("  PICC authenticated."),
                Err(e) => {
                    eprintln!("  PICC auth failed: {e:?}");
                    return;
                }
            }
        }
        match desfire.delete_application(args.aid) {
            Ok(()) => println!("  Deleted application 0x{:06X}.", args.aid.as_u32()),
            Err(e) => eprintln!("  DeleteApplication failed: {e:?}"),
        }
    } else {
        // Files specified: select app, auth at app level, delete each file.
        if let Err(e) = desfire.select_application(args.aid) {
            eprintln!("  SelectApplication failed: {e:?}");
            return;
        }
        if let Some(auth) = args.auth {
            let rnd_a = match random_rnd_a() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  /dev/urandom: {e}");
                    return;
                }
            };
            match desfire.authenticate_aes_with_rnd_a(auth.key_number, &auth.key, rnd_a) {
                Ok(_) => println!("  App authenticated."),
                Err(e) => {
                    eprintln!("  App auth failed: {e:?}");
                    return;
                }
            }
        }
        for file_id in &args.files {
            match desfire.delete_file(*file_id) {
                Ok(()) => println!("  Deleted file {}.", file_id.as_byte()),
                Err(e) => eprintln!("  DeleteFile({}) failed: {e:?}", file_id.as_byte()),
            }
        }
    }
}

fn read_gallagher_tag<T: Tag + Transport>(tag: &mut T, args: &ReadArgs) {
    if !args.desfire_only {
        read_gallagher_classic_tag(tag);
    }

    read_gallagher_desfire_tag(tag, args);
}

fn read_gallagher_classic_tag<T: Tag>(tag: &mut T) {
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

fn read_gallagher_desfire_tag<T: Transport>(transport: &mut T, args: &ReadArgs) {
    println!("\n=== DESFire Credentials ===");
    let rnd_a = match random_rnd_a() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("  /dev/urandom: {error}");
            return;
        }
    };

    let mut desfire = Desfire::new(transport, WrappedFraming);
    match GallagherDesfireReader::read_from_desfire_with_rnd_a(
        &mut desfire,
        args.desfire_key_source,
        rnd_a,
    ) {
        Ok(result) => {
            for credential in &result.credentials {
                let aid = credential.application_id.as_bytes();
                println!(
                    "  AID {:02X}{:02X}{:02X} file {:02X} | Region {} ({}) | Facility {:>5} | Card {:>8} | Issue {}",
                    aid[2],
                    aid[1],
                    aid[0],
                    credential.file_id.as_byte(),
                    credential.credential.region_code,
                    credential.credential.region_code_letter(),
                    credential.credential.facility_code,
                    credential.credential.card_number,
                    credential.credential.issue_level,
                );
            }
        }
        Err(error) => eprintln!("  DESFire credential read failed: {error:?}"),
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
        run_desfire_auth_pass(desfire, application_id, auth_spec, &file_settings, args);
    }
}

fn run_desfire_auth_pass<T: Transport, C: FrameCodec>(
    desfire: &mut Desfire<T, C>,
    application_id: ApplicationId,
    auth_spec: DesfireAuthSpec,
    file_settings: &[(FileId, Option<FileSettings>)],
    args: &DesfireArgs,
) {
    println!(
        "\n  --- {} auth (key {}, AID 0x{:06X}) ---",
        auth_spec.name(),
        auth_spec.key_number().as_byte(),
        application_id.as_u32()
    );
    if let Err(error) = desfire.select_application(application_id) {
        eprintln!("    SelectApplication failed: {error:?}");
        return;
    }

    let auth_result = match auth_spec {
        DesfireAuthSpec::Aes(spec) => {
            let rnd_a = match random_rnd_a() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("    /dev/urandom failed: {error}");
                    return;
                }
            };
            desfire.authenticate_aes_with_rnd_a(spec.key_number, &spec.key, rnd_a)
        }
        DesfireAuthSpec::Des(spec) => {
            let rnd_a = match random_rnd_a8() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("    /dev/urandom failed: {error}");
                    return;
                }
            };
            desfire.authenticate_des_with_rnd_a(spec.key_number, &spec.key, rnd_a)
        }
        DesfireAuthSpec::Tdea2(spec) => {
            let rnd_a = match random_rnd_a8() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("    /dev/urandom failed: {error}");
                    return;
                }
            };
            desfire.authenticate_2tdea_with_rnd_a(spec.key_number, &spec.key, rnd_a)
        }
        DesfireAuthSpec::Tdea3(spec) => {
            let rnd_a = match random_rnd_a() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("    /dev/urandom failed: {error}");
                    return;
                }
            };
            desfire.authenticate_3tdea_with_rnd_a(spec.key_number, &spec.key, rnd_a)
        }
    };

    if let Err(error) = auth_result {
        eprintln!("    Authenticate{} failed: {error:?}", auth_spec.name());
        return;
    }
    println!("    Authenticated.");

    for (file_id, settings) in file_settings {
        let Some(settings) = settings else { continue };
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
        match settings.communication_mode() {
            CommunicationMode::Plain => {
                // When authenticated, the card sends a response MAC for plain files too.
                // Using read_data_maced keeps our CMAC state in sync with the card.
                match desfire.read_data_maced(*file_id, offset, size, &mut data) {
                    Ok(()) => println!(
                        "    File {} (plain, auth): {:02X?}",
                        file_id.as_byte(),
                        data.as_slice()
                    ),
                    Err(error) => eprintln!(
                        "    File {} ReadData(auth) failed: {error:?}",
                        file_id.as_byte()
                    ),
                }
            }
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
        }
    }

    if args.write {
        run_desfire_write_pass(desfire, file_settings);
    }
}

fn run_desfire_write_pass<T: Transport, C: FrameCodec>(
    desfire: &mut Desfire<T, C>,
    file_settings: &[(FileId, Option<FileSettings>)],
) {
    println!("\n  --- write pass ---");
    for (file_id, settings) in file_settings {
        let Some(settings) = settings else { continue };
        let FileSettingsDetails::Data { size } = settings.details() else {
            println!("    File {}: skipped (not a data file)", file_id.as_byte());
            continue;
        };
        if size.as_u32() == 0 {
            println!("    File {}: skipped (size=0)", file_id.as_byte());
            continue;
        }
        if size.as_u32() > 256 {
            println!(
                "    File {}: skipped ({} bytes exceeds CLI limit)",
                file_id.as_byte(),
                size.as_u32()
            );
            continue;
        }

        let data = match random_bytes(size.as_u32() as usize) {
            Ok(b) => b,
            Err(error) => {
                eprintln!(
                    "    File {}: /dev/urandom failed: {error}",
                    file_id.as_byte()
                );
                continue;
            }
        };

        let offset = U24::new(0).unwrap();
        let mode = settings.communication_mode();
        let result = match mode {
            CommunicationMode::Plain => desfire.write_data(*file_id, offset, &data),
            CommunicationMode::Maced => desfire.write_data_maced(*file_id, offset, &data),
            CommunicationMode::Enciphered => desfire.write_data_enciphered(*file_id, offset, &data),
        };
        match result {
            Ok(()) => println!(
                "    File {} ({}): wrote {:02X?}",
                file_id.as_byte(),
                communication_mode_name(mode),
                data.as_slice()
            ),
            Err(error) => eprintln!(
                "    File {} WriteData({}) failed: {error:?}",
                file_id.as_byte(),
                communication_mode_name(mode)
            ),
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
    let Some((session_key, pre_chaining)) = session.aes_state() else {
        eprintln!("      debug only supported for AES sessions");
        return;
    };
    let pre_iv = pre_chaining.state();

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
    let post_iv = session.aes_state().expect("still AES session").1.state();

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
