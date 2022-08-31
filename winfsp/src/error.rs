use thiserror::Error;
use windows::core::{Error, HRESULT};
use windows::Win32::Foundation::{NTSTATUS, WIN32_ERROR};
use winfsp_sys::FspNtStatusFromWin32;

#[derive(Error, Debug)]
pub enum FspError {
    #[error("HRESULT")]
    HRESULT(HRESULT),
    #[error("WIN32_ERROR")]
    WIN32(WIN32_ERROR),
    #[error("NTRESULT")]
    NTSTATUS(NTSTATUS),
}

impl FspError {
    #[inline(always)]
    pub fn as_ntstatus(&self) -> winfsp_sys::NTSTATUS {
        match self {
            FspError::HRESULT(h) => unsafe { FspNtStatusFromWin32(h.0 as u32) },
            FspError::WIN32(e) => {
                unsafe { FspNtStatusFromWin32(e.0 as u32) }
                // e.0 as i32
            }
            FspError::NTSTATUS(e) => e.0,
        }
    }
}

pub type Result<T> = std::result::Result<T, FspError>;

impl From<HRESULT> for FspError {
    fn from(h: HRESULT) -> Self {
        FspError::HRESULT(h)
    }
}

impl From<WIN32_ERROR> for FspError {
    fn from(h: WIN32_ERROR) -> Self {
        FspError::WIN32(h)
    }
}

impl From<NTSTATUS> for FspError {
    fn from(h: NTSTATUS) -> Self {
        FspError::NTSTATUS(h)
    }
}

impl From<windows::core::Error> for FspError {
    fn from(e: Error) -> Self {
        match WIN32_ERROR::from_error(&e) {
            None => FspError::HRESULT(e.code()),
            Some(w) => FspError::WIN32(w),
        }
    }
}
