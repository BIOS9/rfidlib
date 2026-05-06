use crate::mifare::desfire::{crypto::AesSessionKey, key::KeyNumber};

/// Authentication state for a `DESFire` command stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Unauthenticated,
    Authenticated(AuthenticatedSession),
}

/// Minimal authenticated-session metadata.
///
/// Session keys, IV/chaining state, and command counters belong here once
/// secure messaging is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedSession {
    key_number: KeyNumber,
    session_key: SessionKey,
}

impl AuthenticatedSession {
    /// Creates session metadata for a successful AES authentication.
    pub const fn new_aes(key_number: KeyNumber, session_key: AesSessionKey) -> Self {
        Self {
            key_number,
            session_key: SessionKey::Aes(session_key),
        }
    }

    /// Key number used for the current authentication.
    pub const fn key_number(self) -> KeyNumber {
        self.key_number
    }

    /// Session key negotiated by the current authentication.
    pub const fn session_key(self) -> SessionKey {
        self.session_key
    }
}

/// Authenticated secure-messaging key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKey {
    Aes(AesSessionKey),
}
