use std::ops::Deref;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[derive(Clone)]
pub struct SafeDropHandle(HANDLE);

impl Drop for SafeDropHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl Deref for SafeDropHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HANDLE> for SafeDropHandle {
    fn from(h: HANDLE) -> Self {
        Self(h)
    }
}

impl From<SafeDropHandle> for HANDLE {
    fn from(h: SafeDropHandle) -> Self {
        h.0
    }
}
