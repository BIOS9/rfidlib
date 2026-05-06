use heapless::Vec;

use crate::mifare::desfire::{
    command::CommandCode,
    crypto::{AesCmacChaining, AesSessionKey, DesfireMac},
    error::Error,
    key::KeyNumber,
    status::Status,
};

const MAX_CMAC_INPUT_SIZE: usize = 256;

/// Authentication state for a `DESFire` command stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Unauthenticated,
    Authenticated(AuthenticatedSession),
}

/// Authenticated-session metadata and secure-messaging state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedSession {
    key_number: KeyNumber,
    session_key: SessionKey,
    cmac_chaining: AesCmacChaining,
}

impl AuthenticatedSession {
    /// Creates session metadata for a successful AES authentication.
    pub const fn new_aes(key_number: KeyNumber, session_key: AesSessionKey) -> Self {
        Self {
            key_number,
            session_key: SessionKey::Aes(session_key),
            cmac_chaining: AesCmacChaining::new(),
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

    /// Current CMAC chaining state.
    pub const fn cmac_chaining(self) -> AesCmacChaining {
        self.cmac_chaining
    }

    /// Replaces the current secure-messaging chaining state.
    pub const fn set_chaining_state(&mut self, state: [u8; 16]) {
        self.cmac_chaining = AesCmacChaining::from_state(state);
    }

    /// Calculates and stores the next command CMAC for this session.
    pub fn update_command_cmac(
        &mut self,
        command_code: CommandCode,
        command_data: &[u8],
    ) -> Result<DesfireMac, Error> {
        let mut input: Vec<u8, MAX_CMAC_INPUT_SIZE> = Vec::new();
        input
            .push(command_code.as_byte())
            .map_err(|_| Error::CommandTooLong)?;
        input
            .extend_from_slice(command_data)
            .map_err(|_| Error::CommandTooLong)?;

        match self.session_key {
            SessionKey::Aes(session_key) => Ok(self
                .cmac_chaining
                .update(session_key, input.as_slice())
                .desfire_mac()),
        }
    }

    /// Calculates and stores the next response CMAC for this session.
    pub fn update_response_cmac(
        &mut self,
        status: Status,
        response_data: &[u8],
    ) -> Result<DesfireMac, Error> {
        let mut input: Vec<u8, MAX_CMAC_INPUT_SIZE> = Vec::new();
        input
            .extend_from_slice(response_data)
            .map_err(|_| Error::ResponseTooLong)?;
        input
            .push(status.as_byte())
            .map_err(|_| Error::ResponseTooLong)?;

        match self.session_key {
            SessionKey::Aes(session_key) => Ok(self
                .cmac_chaining
                .update(session_key, input.as_slice())
                .desfire_mac()),
        }
    }
}

/// Authenticated secure-messaging key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKey {
    Aes(AesSessionKey),
}

#[cfg(test)]
mod tests {
    use crate::mifare::desfire::{
        command::CommandCode,
        crypto::{AesCmac, AesSessionKey},
        key::KeyNumber,
        session::AuthenticatedSession,
    };

    #[test]
    fn command_cmac_updates_session_chaining_state() {
        let session_key = AesSessionKey::new([
            0x01, 0x02, 0x03, 0x04, 0x47, 0xDB, 0x4F, 0x91, 0x13, 0x14, 0x15, 0x16, 0x6E, 0xC6,
            0x58, 0x25,
        ]);
        let mut session = AuthenticatedSession::new_aes(KeyNumber::new(0).unwrap(), session_key);

        let mac = session
            .update_command_cmac(
                CommandCode::READ_DATA,
                &[0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00],
            )
            .unwrap();
        let expected_full_cmac = AesCmac::calculate(
            &session_key.as_bytes(),
            &[0xBD, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00],
        );

        assert_eq!(mac, expected_full_cmac.desfire_mac());
        assert_eq!(
            session.cmac_chaining().state(),
            expected_full_cmac.as_bytes()
        );
    }
}
