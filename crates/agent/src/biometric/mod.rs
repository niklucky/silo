//! OS biometric unlock backend (Touch ID on macOS; stubbed on other platforms
//! until Windows Hello / Linux Secret Service support is added).
//!
//! The vault's account key is wrapped into a [`silo_core::UnlockSlot`] under a
//! random 32-byte key stored in the OS keychain (`key_id` in `biometric.json`).
//! Unlocking prompts for OS biometrics first, then retrieves the wrapping key
//! from the keychain and unwraps the slot in `silo-core`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use silo_core::UnlockSlot;
use silo_core::crypto::KEY_LEN;
use zeroize::Zeroizing;

/// Domain context bound into the [`UnlockSlot`] AAD and HKDF info.
pub const BIOMETRIC_CONTEXT: &[u8] = b"os-biometric";

/// On-disk record stored at `$SILO_HOME/biometric.json`. Contains no secrets:
/// the wrapping key lives in the OS keychain under `key_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricRecord {
    pub key_id: String,
    pub slot: UnlockSlot,
}

#[derive(Debug, thiserror::Error)]
pub enum BiometricError {
    #[error("biometric unlock is not available: {0}")]
    Unavailable(String),
    #[error("biometric authentication cancelled")]
    Cancelled,
    #[error("biometric unlock key not found in keychain; disable and re-enable Touch ID unlock")]
    KeyNotFound,
    #[error("{0}")]
    Failed(String),
}

pub trait BiometricProvider: Send + Sync {
    fn is_available(&self) -> bool;
    fn authenticate(&self, reason: &str) -> Result<(), BiometricError>;
    fn store_key(&self, account: &str, key: &[u8; KEY_LEN]) -> Result<(), BiometricError>;
    fn load_key(&self, account: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, BiometricError>;
    fn delete_key(&self, account: &str) -> Result<(), BiometricError>;
}

/// Returns the platform's default biometric provider.
pub fn system_provider() -> Arc<dyn BiometricProvider> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacOsBiometric)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(UnsupportedBiometric)
    }
}

#[cfg(not(target_os = "macos"))]
struct UnsupportedBiometric;

#[cfg(not(target_os = "macos"))]
impl BiometricProvider for UnsupportedBiometric {
    fn is_available(&self) -> bool {
        false
    }

    fn authenticate(&self, _reason: &str) -> Result<(), BiometricError> {
        Err(BiometricError::Unavailable(
            "not supported on this platform".to_owned(),
        ))
    }

    fn store_key(&self, _account: &str, _key: &[u8; KEY_LEN]) -> Result<(), BiometricError> {
        Err(BiometricError::Unavailable(
            "not supported on this platform".to_owned(),
        ))
    }

    fn load_key(&self, _account: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, BiometricError> {
        Err(BiometricError::Unavailable(
            "not supported on this platform".to_owned(),
        ))
    }

    fn delete_key(&self, _account: &str) -> Result<(), BiometricError> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString, c_char, c_int};

    use super::*;

    const ERR_BUF_LEN: usize = 512;

    unsafe extern "C" {
        fn silo_biometric_available() -> bool;
        fn silo_biometric_authenticate(
            reason: *const c_char,
            err_buf: *mut c_char,
            err_len: usize,
        ) -> c_int;
        fn silo_keychain_store(
            account: *const c_char,
            key: *const u8,
            key_len: usize,
            err_buf: *mut c_char,
            err_len: usize,
        ) -> c_int;
        fn silo_keychain_load(
            account: *const c_char,
            out_key: *mut u8,
            expected_len: usize,
            err_buf: *mut c_char,
            err_len: usize,
        ) -> c_int;
        fn silo_keychain_delete(
            account: *const c_char,
            err_buf: *mut c_char,
            err_len: usize,
        ) -> c_int;
    }

    pub(super) struct MacOsBiometric;

    impl BiometricProvider for MacOsBiometric {
        fn is_available(&self) -> bool {
            // SAFETY: stateless Objective-C query via LocalAuthentication.
            unsafe { silo_biometric_available() }
        }

        fn authenticate(&self, reason: &str) -> Result<(), BiometricError> {
            let reason = CString::new(reason)
                .map_err(|_| BiometricError::Failed("invalid prompt reason".to_owned()))?;
            let mut err_buf = [0 as c_char; ERR_BUF_LEN];
            // SAFETY: pointers are valid for the duration of the synchronous FFI call.
            let code = unsafe {
                silo_biometric_authenticate(reason.as_ptr(), err_buf.as_mut_ptr(), err_buf.len())
            };
            match code {
                0 => Ok(()),
                1 => Err(BiometricError::Cancelled),
                2 => Err(BiometricError::Unavailable(read_err(
                    &err_buf,
                    "Touch ID is not available",
                ))),
                _ => Err(BiometricError::Failed(read_err(
                    &err_buf,
                    "biometric authentication failed",
                ))),
            }
        }

        fn store_key(&self, account: &str, key: &[u8; KEY_LEN]) -> Result<(), BiometricError> {
            let account = CString::new(account)
                .map_err(|_| BiometricError::Failed("invalid keychain account".to_owned()))?;
            let mut err_buf = [0 as c_char; ERR_BUF_LEN];
            // SAFETY: pointers are valid for the duration of the call.
            let code = unsafe {
                silo_keychain_store(
                    account.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    err_buf.as_mut_ptr(),
                    err_buf.len(),
                )
            };
            if code == 0 {
                Ok(())
            } else {
                Err(BiometricError::Failed(read_err(
                    &err_buf,
                    "could not save unlock key to Keychain",
                )))
            }
        }

        fn load_key(&self, account: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, BiometricError> {
            let account = CString::new(account)
                .map_err(|_| BiometricError::Failed("invalid keychain account".to_owned()))?;
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            let mut err_buf = [0 as c_char; ERR_BUF_LEN];
            // SAFETY: pointers are valid for the duration of the call.
            let code = unsafe {
                silo_keychain_load(
                    account.as_ptr(),
                    key.as_mut_ptr(),
                    key.len(),
                    err_buf.as_mut_ptr(),
                    err_buf.len(),
                )
            };
            match code {
                0 => Ok(key),
                1 => Err(BiometricError::KeyNotFound),
                _ => Err(BiometricError::Failed(read_err(
                    &err_buf,
                    "could not read unlock key from Keychain",
                ))),
            }
        }

        fn delete_key(&self, account: &str) -> Result<(), BiometricError> {
            let account = CString::new(account)
                .map_err(|_| BiometricError::Failed("invalid keychain account".to_owned()))?;
            let mut err_buf = [0 as c_char; ERR_BUF_LEN];
            // SAFETY: pointers are valid for the duration of the call.
            let code = unsafe {
                silo_keychain_delete(account.as_ptr(), err_buf.as_mut_ptr(), err_buf.len())
            };
            if code == 0 {
                Ok(())
            } else {
                Err(BiometricError::Failed(read_err(
                    &err_buf,
                    "could not remove unlock key from Keychain",
                )))
            }
        }
    }

    fn read_err(buf: &[c_char], fallback: &str) -> String {
        // SAFETY: `copy_message` always NUL-terminates `buf` and `buf` starts zeroed.
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .trim()
            .to_owned();
        if s.is_empty() { fallback.to_owned() } else { s }
    }
}
