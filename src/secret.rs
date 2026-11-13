//! Encrypt secrets at rest with the Windows Data Protection API (DPAPI).
//!
//! Stored passwords are sealed with `CryptProtectData`, which derives a key from the current
//! Windows user account. The ciphertext in the database is useless on another account or PC and
//! cannot be read without logging in as this user - a real improvement over the reference app,
//! which kept passwords in plain text. Off Windows (or if DPAPI ever fails) the bytes are stored
//! as-is, so the app still works; the data directory is per-user either way.

/// Seal a UTF-8 secret for storage. Returns opaque bytes to put in the database.
pub fn seal(plaintext: &str) -> Vec<u8> {
    protect(plaintext.as_bytes()).unwrap_or_else(|| plaintext.as_bytes().to_vec())
}

/// Reverse [`seal`]. Falls back to treating the bytes as plain UTF-8 (e.g. a value written on a
/// platform without DPAPI).
pub fn open(sealed: &[u8]) -> String {
    unprotect(sealed)
        .and_then(|b| String::from_utf8(b).ok())
        .or_else(|| String::from_utf8(sealed.to_vec()).ok())
        .unwrap_or_default()
}

#[cfg(windows)]
fn protect(data: &[u8]) -> Option<Vec<u8>> {
    dpapi(data, true)
}

#[cfg(windows)]
fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    // CryptProtectData reads pbData but does not modify it; the cast is only to match the ABI.
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: both blobs are valid for the call; `output.pbData` is freed with LocalFree below.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &mut input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };

    if ok == 0 || output.pbData.is_null() {
        return None;
    }
    // SAFETY: Windows returned `cbData` valid bytes at `pbData`.
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Some(bytes)
}

#[cfg(not(windows))]
fn protect(_data: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(not(windows))]
fn unprotect(_data: &[u8]) -> Option<Vec<u8>> {
    None
}
