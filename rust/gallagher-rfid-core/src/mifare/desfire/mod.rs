//! Core MIFARE `DESFire` primitives.
//!
//! This module keeps hardware transport, native/wrapped framing, command
//! representation, and security/session concepts separate. Higher-level
//! `DESFire` commands and vendor credential formats should build on these types.

pub mod application;
pub mod command;
pub mod error;
pub mod file;
pub mod framing;
pub mod key;
pub mod session;
pub mod status;
pub mod transport;
pub mod types;

pub use application::ApplicationId;
pub use command::{Command, CommandCode, Response};
pub use error::Error;
pub use file::{AccessRights, CommunicationMode, FileId, FileSettings, FileType};
pub use framing::{FrameCodec, NativeFraming, WrappedFraming};
pub use key::{Key, KeyNumber};
pub use session::{AuthenticatedSession, Session};
pub use status::Status;
pub use transport::{Frame, Transport, MAX_FRAME_SIZE};
