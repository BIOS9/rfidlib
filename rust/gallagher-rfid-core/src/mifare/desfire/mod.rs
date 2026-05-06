//! Core MIFARE `DESFire` primitives.
//!
//! This module keeps hardware transport, native/wrapped framing, command
//! representation, and security/session concepts separate. Higher-level
//! `DESFire` commands and vendor credential formats should build on these types.

pub mod application;
pub mod client;
pub mod command;
pub mod error;
pub mod executor;
pub mod file;
pub mod framing;
pub mod key;
pub mod session;
pub mod status;
pub mod transport;
pub mod types;
pub mod version;

pub use application::ApplicationId;
pub use client::Desfire;
pub use command::{Command, CommandCode, Response};
pub use error::Error;
pub use executor::{Executor, MAX_ADDITIONAL_FRAMES};
pub use file::{
    AccessCondition, AccessRights, CommunicationMode, FileId, FileSettings, FileSettingsDetails,
    FileType,
};
pub use framing::{FrameCodec, NativeFraming, WrappedFraming};
pub use key::{ApplicationKeyType, Key, KeyNumber, KeySettings};
pub use session::{AuthenticatedSession, Session};
pub use status::Status;
pub use transport::{Frame, Transport, MAX_FRAME_SIZE};
pub use types::U24;
pub use version::{VersionInfo, VersionPart};
