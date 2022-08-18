use windows::core::{Result, PWSTR};
use windows::Win32::Foundation::STATUS_SUCCESS;
pub use winfsp_sys::FSP_FSCTL_DIR_INFO;
use winfsp_sys::{
    FspFileSystemAcquireDirectoryBufferEx, FspFileSystemDeleteDirectoryBuffer,
    FspFileSystemFillDirectoryBuffer, FspFileSystemReadDirectoryBuffer,
    FspFileSystemReleaseDirectoryBuffer, PVOID,
};

pub struct DirBuffer(*mut PVOID);
pub struct DirBufferLock<'a>(&'a mut DirBuffer);

impl Default for DirBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DirBuffer {
    pub fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    pub fn acquire(&mut self, reset: bool, capacity_hint: Option<u32>) -> Result<DirBufferLock> {
        let mut result = STATUS_SUCCESS;
        unsafe {
            if FspFileSystemAcquireDirectoryBufferEx(
                self.0,
                reset.into(),
                capacity_hint.unwrap_or(0),
                &mut result.0,
            ) != 0
            {
                Ok(DirBufferLock(self))
            } else {
                Err(result.into())
            }
        }
    }

    pub fn read<M: Into<PWSTR>>(&self, marker: M, buffer: &mut [u8]) -> u32 {
        let mut out = 0u32;
        unsafe {
            FspFileSystemReadDirectoryBuffer(
                self.0,
                marker.into().0,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut out,
            );
        }
        out
    }
}

impl DirBufferLock<'_> {
    pub fn fill(&mut self, dir_info: &mut FSP_FSCTL_DIR_INFO) -> Result<()> {
        let mut status = STATUS_SUCCESS;
        unsafe {
            if FspFileSystemFillDirectoryBuffer(self.0 .0, dir_info, &mut status.0) == 0 {
                return Err(status.into());
            }
        }
        Ok(())
    }
}

impl Drop for DirBuffer {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                FspFileSystemDeleteDirectoryBuffer(self.0);
            }
        }
    }
}

impl Drop for DirBufferLock<'_> {
    fn drop(&mut self) {
        unsafe { FspFileSystemReleaseDirectoryBuffer(self.0 .0) }
    }
}
