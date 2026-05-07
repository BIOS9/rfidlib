use heapless::Vec;

use crate::mifare::desfire::{error::Error, status::Status, transport::MAX_FRAME_SIZE};

/// Maximum payload length representable in a short `DESFire` frame.
pub const MAX_COMMAND_DATA_SIZE: usize = 255;

/// Fixed-capacity command payload.
pub type CommandData = Vec<u8, MAX_COMMAND_DATA_SIZE>;

/// `DESFire` native command code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandCode(u8);

impl CommandCode {
    pub const ADDITIONAL_FRAME: Self = Self(0xAF);
    pub const AUTHENTICATE_AES: Self = Self(0xAA);
    pub const GET_KEY_SETTINGS: Self = Self(0x45);
    pub const GET_KEY_VERSION: Self = Self(0x64);
    pub const GET_VERSION: Self = Self(0x60);
    pub const GET_APPLICATION_IDS: Self = Self(0x6A);
    pub const FORMAT_PICC: Self = Self(0xFC);
    pub const CREATE_APPLICATION: Self = Self(0xCA);
    pub const DELETE_APPLICATION: Self = Self(0xDA);
    pub const SELECT_APPLICATION: Self = Self(0x5A);
    pub const FREE_MEM: Self = Self(0x6E);
    pub const GET_FILE_IDS: Self = Self(0x6F);
    pub const GET_FILE_SETTINGS: Self = Self(0xF5);
    pub const CREATE_STD_DATA_FILE: Self = Self(0xCD);
    pub const CREATE_BACKUP_DATA_FILE: Self = Self(0xCB);
    pub const CREATE_VALUE_FILE: Self = Self(0xCC);
    pub const CREATE_LINEAR_RECORD_FILE: Self = Self(0xC1);
    pub const CREATE_CYCLIC_RECORD_FILE: Self = Self(0xC0);
    pub const DELETE_FILE: Self = Self(0xDF);
    pub const READ_DATA: Self = Self(0xBD);
    pub const WRITE_DATA: Self = Self(0x3D);

    /// Creates a command code from its raw `DESFire` byte.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Raw `DESFire` command byte.
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

/// Canonical `DESFire` command before native or wrapped framing is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    code: CommandCode,
    data: CommandData,
}

impl Command {
    /// Builds a command from a code and payload.
    pub fn new(code: CommandCode, data: &[u8]) -> Result<Self, Error> {
        let mut out = CommandData::new();
        out.extend_from_slice(data)
            .map_err(|_| Error::CommandTooLong)?;
        Ok(Self { code, data: out })
    }

    /// Builds the `DESFire` additional-frame command.
    pub fn additional_frame() -> Self {
        Self {
            code: CommandCode::ADDITIONAL_FRAME,
            data: CommandData::new(),
        }
    }

    /// `DESFire` command code.
    pub const fn code(&self) -> CommandCode {
        self.code
    }

    /// Command payload bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Canonical `DESFire` response after native or wrapped framing is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: Status,
    data: Vec<u8, MAX_FRAME_SIZE>,
}

impl Response {
    /// Builds an empty response with the supplied status.
    pub fn new(status: Status) -> Self {
        Self {
            status,
            data: Vec::new(),
        }
    }

    /// Replaces the response content.
    pub fn set(&mut self, status: Status, data: &[u8]) -> Result<(), Error> {
        self.status = status;
        self.data.clear();
        self.data
            .extend_from_slice(data)
            .map_err(|_| Error::MalformedResponse)
    }

    /// `DESFire` status byte decoded into a typed status.
    pub const fn status(&self) -> Status {
        self.status
    }

    /// Response payload bytes with the status removed.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
