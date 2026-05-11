#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unsafe_code)]

use core::{ptr, slice};

use tapsmith_core::gallagher::credential::GallagherCredential;

pub const TAPSMITH_ABI_VERSION: u32 = 1;
pub const TAPSMITH_GALLAGHER_CREDENTIAL_LEN: usize = 8;

pub type TapsmithStatus = i32;

pub const TAPSMITH_STATUS_OK: TapsmithStatus = 0;
pub const TAPSMITH_STATUS_NULL_POINTER: TapsmithStatus = 1;
pub const TAPSMITH_STATUS_INVALID_LENGTH: TapsmithStatus = 2;
pub const TAPSMITH_STATUS_INVALID_CREDENTIAL: TapsmithStatus = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapsmithGallagherCredential {
    pub region_code: u8,
    pub facility_code: u16,
    pub card_number: u32,
    pub issue_level: u8,
}

#[no_mangle]
pub extern "C" fn tapsmith_abi_version() -> u32 {
    TAPSMITH_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn tapsmith_gallagher_credential_len() -> usize {
    TAPSMITH_GALLAGHER_CREDENTIAL_LEN
}

/// Decodes an 8-byte encoded Gallagher credential.
///
/// # Safety
///
/// `data` must point to `data_len` readable bytes. `out_credential` must point
/// to writable memory for one `TapsmithGallagherCredential`.
#[no_mangle]
pub unsafe extern "C" fn tapsmith_gallagher_credential_decode(
    data: *const u8,
    data_len: usize,
    out_credential: *mut TapsmithGallagherCredential,
) -> TapsmithStatus {
    if data.is_null() || out_credential.is_null() {
        return TAPSMITH_STATUS_NULL_POINTER;
    }
    if data_len != TAPSMITH_GALLAGHER_CREDENTIAL_LEN {
        return TAPSMITH_STATUS_INVALID_LENGTH;
    }

    let data = unsafe { slice::from_raw_parts(data, data_len) };
    let mut bytes = [0; TAPSMITH_GALLAGHER_CREDENTIAL_LEN];
    bytes.copy_from_slice(data);

    match GallagherCredential::decode(&bytes) {
        Ok(credential) => {
            unsafe { ptr::write(out_credential, credential.into()) };
            TAPSMITH_STATUS_OK
        }
        Err(_) => TAPSMITH_STATUS_INVALID_CREDENTIAL,
    }
}

/// Encodes a Gallagher credential into its 8-byte card representation.
///
/// # Safety
///
/// `credential` must point to one readable `TapsmithGallagherCredential`.
/// `out_data` must point to `out_data_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn tapsmith_gallagher_credential_encode(
    credential: *const TapsmithGallagherCredential,
    out_data: *mut u8,
    out_data_len: usize,
) -> TapsmithStatus {
    if credential.is_null() || out_data.is_null() {
        return TAPSMITH_STATUS_NULL_POINTER;
    }
    if out_data_len != TAPSMITH_GALLAGHER_CREDENTIAL_LEN {
        return TAPSMITH_STATUS_INVALID_LENGTH;
    }

    let credential = unsafe { *credential };
    let Ok(credential) = GallagherCredential::new(
        credential.region_code,
        credential.facility_code,
        credential.card_number,
        credential.issue_level,
    ) else {
        return TAPSMITH_STATUS_INVALID_CREDENTIAL;
    };

    let encoded = credential.encode();
    unsafe {
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            out_data,
            TAPSMITH_GALLAGHER_CREDENTIAL_LEN,
        );
    }
    TAPSMITH_STATUS_OK
}

impl From<GallagherCredential> for TapsmithGallagherCredential {
    fn from(credential: GallagherCredential) -> Self {
        Self {
            region_code: credential.region_code,
            facility_code: credential.facility_code,
            card_number: credential.card_number,
            issue_level: credential.issue_level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED: [u8; TAPSMITH_GALLAGHER_CREDENTIAL_LEN] =
        [0x20, 0xA1, 0xFC, 0x12, 0x04, 0x05, 0xA3, 0x59];

    #[test]
    fn reports_abi_version() {
        assert_eq!(tapsmith_abi_version(), 1);
    }

    #[test]
    fn reports_gallagher_credential_len() {
        assert_eq!(
            tapsmith_gallagher_credential_len(),
            TAPSMITH_GALLAGHER_CREDENTIAL_LEN
        );
    }

    #[test]
    fn decodes_gallagher_credential() {
        let mut credential = TapsmithGallagherCredential {
            region_code: 0,
            facility_code: 0,
            card_number: 0,
            issue_level: 0,
        };

        let status = unsafe {
            tapsmith_gallagher_credential_decode(
                ENCODED.as_ptr(),
                ENCODED.len(),
                ptr::addr_of_mut!(credential),
            )
        };

        assert_eq!(status, TAPSMITH_STATUS_OK);
        assert_eq!(
            credential,
            TapsmithGallagherCredential {
                region_code: 2,
                facility_code: 64_844,
                card_number: 4_123_540,
                issue_level: 12,
            }
        );
    }

    #[test]
    fn encodes_gallagher_credential() {
        let credential = TapsmithGallagherCredential {
            region_code: 2,
            facility_code: 64_844,
            card_number: 4_123_540,
            issue_level: 12,
        };
        let mut encoded = [0; TAPSMITH_GALLAGHER_CREDENTIAL_LEN];

        let status = unsafe {
            tapsmith_gallagher_credential_encode(
                ptr::addr_of!(credential),
                encoded.as_mut_ptr(),
                encoded.len(),
            )
        };

        assert_eq!(status, TAPSMITH_STATUS_OK);
        assert_eq!(encoded, ENCODED);
    }

    #[test]
    fn rejects_null_decode_pointer() {
        let mut credential = TapsmithGallagherCredential {
            region_code: 0,
            facility_code: 0,
            card_number: 0,
            issue_level: 0,
        };

        let status = unsafe {
            tapsmith_gallagher_credential_decode(
                ptr::null(),
                ENCODED.len(),
                ptr::addr_of_mut!(credential),
            )
        };

        assert_eq!(status, TAPSMITH_STATUS_NULL_POINTER);
    }

    #[test]
    fn rejects_invalid_decode_length() {
        let mut credential = TapsmithGallagherCredential {
            region_code: 0,
            facility_code: 0,
            card_number: 0,
            issue_level: 0,
        };

        let status = unsafe {
            tapsmith_gallagher_credential_decode(
                ENCODED.as_ptr(),
                ENCODED.len() - 1,
                ptr::addr_of_mut!(credential),
            )
        };

        assert_eq!(status, TAPSMITH_STATUS_INVALID_LENGTH);
    }

    #[test]
    fn rejects_invalid_credential_for_encode() {
        let credential = TapsmithGallagherCredential {
            region_code: 16,
            facility_code: 0,
            card_number: 0,
            issue_level: 0,
        };
        let mut encoded = [0; TAPSMITH_GALLAGHER_CREDENTIAL_LEN];

        let status = unsafe {
            tapsmith_gallagher_credential_encode(
                ptr::addr_of!(credential),
                encoded.as_mut_ptr(),
                encoded.len(),
            )
        };

        assert_eq!(status, TAPSMITH_STATUS_INVALID_CREDENTIAL);
    }
}
