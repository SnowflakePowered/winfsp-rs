use std::io::{Error, ErrorKind};
use thiserror::Error;
use windows::core::HRESULT;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
    NTSTATUS, WIN32_ERROR,
};

#[cfg(feature = "io-error")]
use windows::Win32::Foundation::{
    ERROR_DIRECTORY, ERROR_DIRECTORY_NOT_SUPPORTED, ERROR_FILENAME_EXCED_RANGE,
};

use winfsp_sys::FspNtStatusFromWin32;

/// Error type for WinFSP.
///
/// WinFSP wraps errors from the [`windows`](https://github.com/microsoft/windows-rs) crate
/// and can coerces errors into the proper NTSTATUS where necessary.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum FspError {
    #[error("HRESULT")]
    /// Wraps a Windows HRESULT.
    HRESULT(i32),
    #[error("WIN32_ERROR")]
    /// Wraps a Windows error returned from `GetLastError`.
    WIN32(u32),
    #[error("NTRESULT")]
    /// Wraps a NTSTATUS error.
    NTSTATUS(i32),
    #[error("IO")]
    /// Wraps a Rust IO [`ErrorKind`](std::io::ErrorKind).
    /// Only a few, limited IO errors are supported. Unsupported IO
    /// errors will panic when transformed into an NTSTATUS value.
    IO(ErrorKind),
}

impl FspError {
    /// Get the corresponding NTSTATUS for this error.
    #[inline(always)]
    pub fn to_ntstatus(&self) -> winfsp_sys::NTSTATUS {
        match self {
            &FspError::HRESULT(h) => unsafe { FspNtStatusFromWin32(h as u32) },
            &FspError::WIN32(e) => {
                unsafe { FspNtStatusFromWin32(e) }
                // e.0 as i32
            }
            FspError::IO(e) => {
                let win32_equiv = match e {
                    ErrorKind::NotFound => ERROR_FILE_NOT_FOUND,
                    ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED,
                    ErrorKind::AlreadyExists => ERROR_ALREADY_EXISTS,
                    ErrorKind::InvalidInput => ERROR_INVALID_PARAMETER,
                    #[cfg(feature = "io-error")]
                    ErrorKind::InvalidFilename => ERROR_FILENAME_EXCED_RANGE,
                    #[cfg(feature = "io-error")]
                    ErrorKind::IsADirectory => ERROR_DIRECTORY_NOT_SUPPORTED,
                    #[cfg(feature = "io-error")]
                    ErrorKind::NotADirectory => ERROR_DIRECTORY,
                    _ =>  return 0xC00000E9u32 as i32, // STATUS_UNEXPECTED_IO_ERROR
                };
                unsafe { FspNtStatusFromWin32(win32_equiv.0) }
            }
            &FspError::NTSTATUS(e) => e,
        }
    }
}

/// Result type for WinFSP.
pub type Result<T> = std::result::Result<T, FspError>;
impl From<std::io::Error> for FspError {
    fn from(e: Error) -> Self {
        // prefer raw error if available
        if let Some(e) = e.raw_os_error() {
            FspError::WIN32(e as u32)
        } else {
            FspError::IO(e.kind())
        }
    }
}

#[cfg(feature = "windows-rs-error")]
impl From<HRESULT> for FspError {
    fn from(h: HRESULT) -> Self {
        FspError::HRESULT(h.0)
    }
}

#[cfg(feature = "windows-rs-error")]
impl From<WIN32_ERROR> for FspError {
    fn from(h: WIN32_ERROR) -> Self {
        FspError::WIN32(h.0)
    }
}

#[cfg(feature = "windows-rs-error")]
impl From<NTSTATUS> for FspError {
    fn from(h: NTSTATUS) -> Self {
        FspError::NTSTATUS(h.0)
    }
}

#[cfg(feature = "windows-rs-error")]
impl From<windows::core::Error> for FspError {
    fn from(e: windows::core::Error) -> Self {
        let code = e.code().0 as u32;
        // https://learn.microsoft.com/en-us/windows/win32/com/structure-of-com-error-codes
        // N bit indicates mapped NTSTATUS.
        if (code & 0x1000_0000) >> 28 == 1 {
            let nt_status = code & !(1 << 28);
            return FspError::NTSTATUS(nt_status as i32);
        }
        match WIN32_ERROR::from_error(&e) {
            None => FspError::HRESULT(e.code().0),
            Some(w) => FspError::WIN32(w.0),
        }
    }
}
