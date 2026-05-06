use crate::mifare::desfire::key::KeyNumber;

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
}

impl AuthenticatedSession {
    /// Creates session metadata for a successful authentication.
    pub const fn new(key_number: KeyNumber) -> Self {
        Self { key_number }
    }

    /// Key number used for the current authentication.
    pub const fn key_number(self) -> KeyNumber {
        self.key_number
    }
}
