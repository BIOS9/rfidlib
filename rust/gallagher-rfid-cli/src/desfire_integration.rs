use std::fs::File;
use std::io::{self, Read, Write};

use gallagher_rfid_core::mifare::desfire::{
    AccessCondition, AccessRights, ApplicationId, ApplicationKeyType, CommunicationMode, Desfire,
    Error, FileId, FileSettingsDetails, KeyNumber, KeySettings, RndA, RndA8, SessionKey, Transport,
    WrappedFraming, U24,
};
use heapless::Vec as HeaplessVec;

const FILE_SIZE: U24 = U24::new(32).unwrap();
const DATA_LEN: usize = 15;
const DATA_READ_LEN: U24 = U24::new(15).unwrap();
const ZERO_DES_KEY: [u8; 8] = [0u8; 8];
const ZERO_2TDEA_KEY: [u8; 16] = [0u8; 16];
const ZERO_3TDEA_KEY: [u8; 24] = [0u8; 24];
const ZERO_AES_KEY: [u8; 16] = [0u8; 16];
const AES_KEY_1: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F,
];

#[derive(Debug, Clone)]
pub struct IntegrationArgs {
    yes: bool,
    skip_format: bool,
    picc_auth: Option<AuthSpec>,
}

#[derive(Debug, Clone, Copy)]
enum AuthSpec {
    Aes {
        key_number: KeyNumber,
        key: [u8; 16],
    },
    Des {
        key_number: KeyNumber,
        key: [u8; 8],
    },
    Tdea2 {
        key_number: KeyNumber,
        key: [u8; 16],
    },
    Tdea3 {
        key_number: KeyNumber,
        key: [u8; 24],
    },
}

#[derive(Debug, Clone, Copy)]
enum TestAlgorithm {
    Tdea2,
    Tdea3,
    Aes,
}

#[derive(Default)]
struct Results {
    passed: usize,
    failed: usize,
    skipped: usize,
}

struct Runner<T: Transport> {
    desfire: Desfire<T, WrappedFraming>,
    args: IntegrationArgs,
    results: Results,
    current_picc_auth: Option<AuthSpec>,
}

pub fn parse_args(args: &[String]) -> Result<IntegrationArgs, String> {
    let mut parsed = IntegrationArgs {
        yes: false,
        skip_format: false,
        picc_auth: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--yes" | "--yes-i-understand-this-erases-tag" => parsed.yes = true,
            "--skip-format" => parsed.skip_format = true,
            "--picc-auth-aes" => {
                let value = iter
                    .next()
                    .ok_or("--picc-auth-aes requires <key_number>:<32_hex>")?;
                set_picc_auth(&mut parsed.picc_auth, parse_aes_auth_spec(value)?)?;
            }
            "--picc-auth-des" => {
                let value = iter
                    .next()
                    .ok_or("--picc-auth-des requires <key_number>:<16_hex>")?;
                set_picc_auth(&mut parsed.picc_auth, parse_des_auth_spec(value)?)?;
            }
            "--picc-auth-2tdea" | "--picc-auth-2k3des" => {
                let value = iter
                    .next()
                    .ok_or("--picc-auth-2tdea requires <key_number>:<32_hex>")?;
                set_picc_auth(&mut parsed.picc_auth, parse_tdea2_auth_spec(value)?)?;
            }
            "--picc-auth-3tdea" | "--picc-auth-3k3des" => {
                let value = iter
                    .next()
                    .ok_or("--picc-auth-3tdea requires <key_number>:<48_hex>")?;
                set_picc_auth(&mut parsed.picc_auth, parse_tdea3_auth_spec(value)?)?;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(parsed)
}

pub fn run<T: Transport>(transport: T, args: IntegrationArgs) -> bool {
    if !args.skip_format && !confirm_destructive(args.yes) {
        eprintln!("desfire-integration: cancelled");
        return false;
    }

    let mut runner = Runner {
        desfire: Desfire::new(transport, WrappedFraming),
        current_picc_auth: args.picc_auth,
        args,
        results: Results::default(),
    };

    println!("=== DESFire Real-Tag Integration Test ===");
    println!("Reader transport is live. This command talks to the real tag currently on the reader.");

    if runner.args.skip_format {
        runner.skip("FormatPICC", "--skip-format supplied");
        let _ = runner.select_picc();
    } else {
        runner.step("Select PICC, authenticate, and FormatPICC", |r| {
            r.select_picc()?;
            r.authenticate_picc()?;
            r.desfire.format_picc().map_err(desfire_error)?;
            r.select_picc()
        });
    }

    runner.step("Read tag version, PICC key settings, and free memory", |r| {
        r.print_tag_info()
    });

    runner.run_algorithm(TestAlgorithm::Tdea2);
    runner.run_algorithm(TestAlgorithm::Tdea3);
    runner.run_algorithm(TestAlgorithm::Aes);

    runner.skip(
        "Change application key settings",
        "ChangeKeySettings is not implemented in the core API yet",
    );
    runner.skip(
        "Rotate PICC key through 3TDEA and AES",
        "PICC ChangeKey is currently implemented for AES only; DES/3DES PICC key change is not implemented yet",
    );

    println!("\n=== Summary ===");
    println!("  passed:  {}", runner.results.passed);
    println!("  failed:  {}", runner.results.failed);
    println!("  skipped: {}", runner.results.skipped);

    runner.results.failed == 0
}

impl<T: Transport> Runner<T> {
    fn run_algorithm(&mut self, algorithm: TestAlgorithm) {
        println!("\n=== {} application chain ===", algorithm.name());
        let aid = algorithm.aid();
        let data = algorithm.test_data();
        let key0_rights = key0_rights();
        let key1_read_rights = key1_read_rights();

        if !self.step("PICC auth for CreateApplication", |r| {
            r.select_picc()?;
            r.authenticate_picc()
        }) {
            return;
        }

        if !self.step("CreateApplication", |r| {
            r.desfire
                .create_application(aid, KeySettings::new(0x0F, algorithm.key_type(), 3))
                .map_err(desfire_error)
        }) {
            return;
        }

        if !self.step("Select application and authenticate key 0", |r| {
            r.select_app(aid)?;
            r.authenticate_app(algorithm, key0())
        }) {
            self.cleanup_app(aid);
            return;
        }

        self.step("GetKeySettings", |r| {
            let settings = r.desfire.get_key_settings().map_err(desfire_error)?;
            if settings.key_type() != algorithm.key_type() || settings.key_count() != 3 {
                return Err(format!(
                    "unexpected settings: type={:?} count={}",
                    settings.key_type(),
                    settings.key_count()
                ));
            }
            println!(
                "       type={:?} count={} raw={:02X} {:02X}",
                settings.key_type(),
                settings.key_count(),
                settings.raw_settings(),
                settings.raw_key_count()
            );
            Ok(())
        });

        if !self.step("Create enciphered standard data file", |r| {
            r.desfire
                .create_std_data_file(data_file(), CommunicationMode::Enciphered, key0_rights, FILE_SIZE)
                .map_err(desfire_error)
        }) {
            self.cleanup_app(aid);
            return;
        }

        self.step("GetFileSettings", |r| {
            let settings = r.desfire.get_file_settings(data_file()).map_err(desfire_error)?;
            if settings.communication_mode() != CommunicationMode::Enciphered {
                return Err(format!(
                    "unexpected communication mode: {:?}",
                    settings.communication_mode()
                ));
            }
            if settings.details() != (FileSettingsDetails::Data { size: FILE_SIZE }) {
                return Err(format!("unexpected details: {:?}", settings.details()));
            }
            Ok(())
        });

        if !self.step("WriteData enciphered", |r| {
            r.desfire
                .write_data_enciphered(data_file(), U24::new(0).unwrap(), &data)
                .map_err(desfire_error)
        }) {
            self.cleanup_app(aid);
            return;
        }

        self.step("ReadData enciphered and verify bytes", |r| {
            r.read_and_verify(&data)
        });

        match algorithm {
            TestAlgorithm::Aes => {
                self.step("Change AES key 1 with AMK/key 0", |r| {
                    r.desfire
                        .change_key_aes(key1(), AES_KEY_1, 0x42, Some(ZERO_AES_KEY))
                        .map_err(desfire_error)
                });
            }
            TestAlgorithm::Tdea2 | TestAlgorithm::Tdea3 => {
                self.skip(
                    &format!("Change {} key 1 with AMK/key 0", algorithm.name()),
                    "DES/3DES ChangeKey is not implemented in the core API yet",
                );
            }
        }

        self.step("Change file read access to key 1", |r| {
            r.desfire
                .change_file_settings(data_file(), CommunicationMode::Enciphered, key1_read_rights)
                .map_err(desfire_error)
        });

        self.step("Re-authenticate with key 1 and read file", |r| {
            r.select_app(aid)?;
            r.authenticate_app(algorithm, key1())?;
            r.read_and_verify(&data)
        });

        self.step("Re-authenticate with key 0 and delete file", |r| {
            r.select_app(aid)?;
            r.authenticate_app(algorithm, key0())?;
            r.desfire.delete_file(data_file()).map_err(desfire_error)
        });

        self.step("PICC auth and DeleteApplication", |r| {
            r.select_picc()?;
            r.authenticate_picc()?;
            r.desfire.delete_application(aid).map_err(desfire_error)
        });
    }

    fn step<F>(&mut self, label: &str, f: F) -> bool
    where
        F: FnOnce(&mut Self) -> Result<(), String>,
    {
        println!("  -> {label}");
        match f(self) {
            Ok(()) => {
                self.results.passed += 1;
                println!("     PASS");
                true
            }
            Err(error) => {
                self.results.failed += 1;
                println!("     FAIL: {error}");
                false
            }
        }
    }

    fn skip(&mut self, label: &str, reason: &str) {
        self.results.skipped += 1;
        println!("  -> {label}");
        println!("     SKIP: {reason}");
    }

    fn select_picc(&mut self) -> Result<(), String> {
        self.desfire
            .select_application(ApplicationId::PICC)
            .map_err(desfire_error)
    }

    fn select_app(&mut self, aid: ApplicationId) -> Result<(), String> {
        self.desfire
            .select_application(aid)
            .map_err(desfire_error)
    }

    fn authenticate_picc(&mut self) -> Result<(), String> {
        if let Some(auth) = self.current_picc_auth.or(self.args.picc_auth) {
            self.select_picc()?;
            authenticate(&mut self.desfire, auth)?;
            self.current_picc_auth = Some(auth);
            println!("       PICC authenticated with {}", auth.name());
            return Ok(());
        }

        let candidates = default_picc_auth_candidates();
        let mut last_error = None;
        for auth in candidates {
            let _ = self.select_picc();
            match authenticate(&mut self.desfire, auth) {
                Ok(()) => {
                    self.current_picc_auth = Some(auth);
                    println!("       PICC authenticated with {}", auth.name());
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(format!(
            "PICC auth failed for default AES/DES/2TDEA/3TDEA zero-key candidates{}",
            last_error.map_or(String::new(), |e| format!("; last error: {e}"))
        ))
    }

    fn authenticate_app(
        &mut self,
        algorithm: TestAlgorithm,
        key_number: KeyNumber,
    ) -> Result<(), String> {
        let auth = algorithm.app_auth(key_number);
        authenticate(&mut self.desfire, auth)?;
        println!("       app authenticated with {}", auth.name());
        Ok(())
    }

    fn read_and_verify(&mut self, expected: &[u8; DATA_LEN]) -> Result<(), String> {
        let mut data: HeaplessVec<u8, 64> = HeaplessVec::new();
        self.desfire
            .read_data_enciphered(
                data_file(),
                U24::new(0).unwrap(),
                DATA_READ_LEN,
                &mut data,
            )
            .map_err(desfire_error)?;
        if data.as_slice() != expected {
            return Err(format!(
                "data mismatch: expected {:02X?}, got {:02X?}",
                expected,
                data.as_slice()
            ));
        }
        println!("       data={:02X?}", data.as_slice());
        Ok(())
    }

    fn print_tag_info(&mut self) -> Result<(), String> {
        self.select_picc()?;
        let version = self.desfire.get_version().map_err(desfire_error)?;
        println!("       UID: {:02X?}", version.uid());
        println!(
            "       HW v{}.{} SW v{}.{}",
            version.hardware().major_decimal(),
            version.hardware().minor_decimal(),
            version.software().major_decimal(),
            version.software().minor_decimal()
        );

        let settings = self.desfire.get_key_settings().map_err(desfire_error)?;
        println!(
            "       PICC key settings raw={:02X} {:02X}, type={:?}, count={}",
            settings.raw_settings(),
            settings.raw_key_count(),
            settings.key_type(),
            settings.key_count()
        );

        match self.desfire.free_memory() {
            Ok(memory) => println!("       free memory: {} bytes", memory.as_u32()),
            Err(error) => println!("       free memory: unavailable ({error:?})"),
        }
        Ok(())
    }

    fn cleanup_app(&mut self, aid: ApplicationId) {
        println!("  -> Best-effort cleanup for AID 0x{:06X}", aid.as_u32());
        let result = (|| {
            self.select_picc()?;
            self.authenticate_picc()?;
            self.desfire.delete_application(aid).map_err(desfire_error)
        })();
        match result {
            Ok(()) => println!("     cleanup deleted app"),
            Err(error) => println!("     cleanup skipped/failed: {error}"),
        }
    }
}

impl TestAlgorithm {
    const fn name(self) -> &'static str {
        match self {
            Self::Tdea2 => "2TDEA",
            Self::Tdea3 => "3TDEA",
            Self::Aes => "AES",
        }
    }

    fn aid(self) -> ApplicationId {
        match self {
            Self::Tdea2 => ApplicationId::new(0x22_D2_EA).unwrap(),
            Self::Tdea3 => ApplicationId::new(0x33_D3_EA).unwrap(),
            Self::Aes => ApplicationId::new(0xA5_A5_A5).unwrap(),
        }
    }

    const fn key_type(self) -> ApplicationKeyType {
        match self {
            Self::Tdea2 => ApplicationKeyType::TwoKey3Des,
            Self::Tdea3 => ApplicationKeyType::ThreeKey3Des,
            Self::Aes => ApplicationKeyType::Aes,
        }
    }

    fn app_auth(self, key_number: KeyNumber) -> AuthSpec {
        match self {
            Self::Tdea2 => AuthSpec::Tdea2 {
                key_number,
                key: ZERO_2TDEA_KEY,
            },
            Self::Tdea3 => AuthSpec::Tdea3 {
                key_number,
                key: ZERO_3TDEA_KEY,
            },
            Self::Aes if key_number == key1() => AuthSpec::Aes {
                key_number,
                key: AES_KEY_1,
            },
            Self::Aes => AuthSpec::Aes {
                key_number,
                key: ZERO_AES_KEY,
            },
        }
    }

    fn test_data(self) -> [u8; DATA_LEN] {
        let seed: u8 = match self {
            Self::Tdea2 => 0x22,
            Self::Tdea3 => 0x33,
            Self::Aes => 0xA5,
        };
        let mut data = [0u8; DATA_LEN];
        for (index, byte) in (0u8..).zip(data.iter_mut()) {
            *byte = seed.wrapping_add(index);
        }
        data
    }
}

impl AuthSpec {
    const fn name(self) -> &'static str {
        match self {
            Self::Aes { .. } => "AES",
            Self::Des { .. } => "DES",
            Self::Tdea2 { .. } => "2TDEA",
            Self::Tdea3 { .. } => "3TDEA",
        }
    }
}

fn authenticate<T: Transport>(
    desfire: &mut Desfire<T, WrappedFraming>,
    auth: AuthSpec,
) -> Result<(), String> {
    let session = match auth {
        AuthSpec::Aes { key_number, key } => {
            let rnd_a = random_rnd_a().map_err(|error| format!("/dev/urandom: {error}"))?;
            desfire
                .authenticate_aes_with_rnd_a(key_number, &key, rnd_a)
                .map_err(desfire_error)?
        }
        AuthSpec::Des { key_number, key } => {
            let rnd_a = random_rnd_a8().map_err(|error| format!("/dev/urandom: {error}"))?;
            desfire
                .authenticate_des_with_rnd_a(key_number, &key, rnd_a)
                .map_err(desfire_error)?
        }
        AuthSpec::Tdea2 { key_number, key } => {
            let rnd_a = random_rnd_a8().map_err(|error| format!("/dev/urandom: {error}"))?;
            desfire
                .authenticate_2tdea_with_rnd_a(key_number, &key, rnd_a)
                .map_err(desfire_error)?
        }
        AuthSpec::Tdea3 { key_number, key } => {
            let rnd_a = random_rnd_a().map_err(|error| format!("/dev/urandom: {error}"))?;
            desfire
                .authenticate_3tdea_with_rnd_a(key_number, &key, rnd_a)
                .map_err(desfire_error)?
        }
    };

    match session.session_key() {
        SessionKey::Aes(key) => println!("       session key: {:02X?}", key.as_bytes()),
        SessionKey::Des(key) => println!("       session key: {:02X?}", key.as_bytes()),
        SessionKey::TwoKey3Des(key) => println!("       session key: {:02X?}", key.as_bytes()),
        SessionKey::ThreeKey3Des(key) => println!("       session key: {:02X?}", key.as_bytes()),
    }
    Ok(())
}

fn default_picc_auth_candidates() -> [AuthSpec; 4] {
    [
        AuthSpec::Aes {
            key_number: key0(),
            key: ZERO_AES_KEY,
        },
        AuthSpec::Tdea2 {
            key_number: key0(),
            key: ZERO_2TDEA_KEY,
        },
        AuthSpec::Tdea3 {
            key_number: key0(),
            key: ZERO_3TDEA_KEY,
        },
        AuthSpec::Des {
            key_number: key0(),
            key: ZERO_DES_KEY,
        },
    ]
}

fn key0_rights() -> AccessRights {
    let key0 = AccessCondition::Key(key0());
    AccessRights::new(key0, key0, key0, key0)
}

fn key1_read_rights() -> AccessRights {
    let key0 = AccessCondition::Key(key0());
    AccessRights::new(AccessCondition::Key(key1()), key0, key0, key0)
}

fn data_file() -> FileId {
    FileId::new(1).unwrap()
}

fn key0() -> KeyNumber {
    KeyNumber::new(0).unwrap()
}

fn key1() -> KeyNumber {
    KeyNumber::new(1).unwrap()
}

fn random_rnd_a() -> io::Result<RndA> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(RndA::new(bytes))
}

fn random_rnd_a8() -> io::Result<RndA8> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(RndA8::new(bytes))
}

fn confirm_destructive(yes: bool) -> bool {
    if yes {
        return true;
    }

    eprintln!("WARNING: this integration test will FormatPICC and delete all applications/files on the tag.");
    eprint!("Type FORMAT to continue: ");
    if io::stderr().flush().is_err() {
        return false;
    }

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .is_ok_and(|_| line.trim() == "FORMAT")
}

fn set_picc_auth(auth: &mut Option<AuthSpec>, value: AuthSpec) -> Result<(), String> {
    if auth.replace(value).is_some() {
        return Err("only one --picc-auth-* option may be supplied".to_string());
    }
    Ok(())
}

fn parse_aes_auth_spec(value: &str) -> Result<AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--picc-auth-aes")?;
    Ok(AuthSpec::Aes { key_number, key })
}

fn parse_des_auth_spec(value: &str) -> Result<AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--picc-auth-des")?;
    Ok(AuthSpec::Des { key_number, key })
}

fn parse_tdea2_auth_spec(value: &str) -> Result<AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--picc-auth-2tdea")?;
    Ok(AuthSpec::Tdea2 { key_number, key })
}

fn parse_tdea3_auth_spec(value: &str) -> Result<AuthSpec, String> {
    let (key_number, key) = parse_keyed_hex_spec(value, "--picc-auth-3tdea")?;
    Ok(AuthSpec::Tdea3 { key_number, key })
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

fn desfire_error(error: Error) -> String {
    format!("{error:?}")
}
