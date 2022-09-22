use std::alloc::Layout;




use widestring::{u16cstr, U16CStr};
use windows::Win32::Foundation::{STATUS_SUCCESS};
use winfsp_sys::{
    FspFileSystemAcquireDirectoryBufferEx, FspFileSystemAddDirInfo,
    FspFileSystemDeleteDirectoryBuffer, FspFileSystemFillDirectoryBuffer,
    FspFileSystemReadDirectoryBuffer, FspFileSystemReleaseDirectoryBuffer, FSP_FSCTL_DIR_INFO,
    FSP_FSCTL_FILE_INFO, PVOID,
};

use crate::error::Result;
use crate::filesystem::WideNameInfo;


#[derive(Debug)]
pub struct DirBuffer(PVOID);
#[derive(Debug)]
pub struct DirBufferLock<'a>(&'a mut DirBuffer);
#[derive(Debug)]
pub struct DirMarker<'a>(pub(crate) Option<&'a U16CStr>);

impl DirMarker<'_> {
    // reset the marker.
    pub fn reset(&mut self) {
        self.0.take();
    }

    /// If this marker exists.
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    // If this marker is the parent directory '..'.
    pub fn is_parent(&self) -> bool {
        if let Some(marker) = self.0 {
            return marker == u16cstr!("..");
        }
        false
    }

    // If this marker is the current directory '.'.
    pub fn is_current(&self) -> bool {
        if let Some(marker) = self.0 {
            return marker == u16cstr!(".");
        }
        false
    }

    // Returns the inner contents of the marker.
    pub fn inner(&self) -> Option<&[u16]> {
        self.0.map(U16CStr::as_slice)
    }

    // Returns the inner contents of the marker.
    // If the inner contents are not validly null-terminated, returns None.
    pub fn inner_as_cstr(&self) -> Option<&U16CStr> {
        self.0
    }
}

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
                &mut self.0,
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

    pub fn read(&mut self, marker: DirMarker, buffer: &mut [u8]) -> u32 {
        let mut out = 0u32;
        unsafe {
            FspFileSystemReadDirectoryBuffer(
                &mut self.0,
                marker
                    .0
                    .map_or(std::ptr::null_mut(), |v| v.as_ptr().cast_mut()),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut out,
            );
        }
        out
    }
}

impl DirBufferLock<'_> {
    /// Write a DirInfo entry into the directory buffer.
    ///
    /// A buffer can accept multiple DirInfos of varying sizes.
    pub fn write<const D: usize>(&mut self, dir_info: &mut DirInfo<D>) -> Result<()> {
        let mut status = STATUS_SUCCESS;
        unsafe {
            let buffer = &mut self.0;
            // this is cursed.
            if FspFileSystemFillDirectoryBuffer(
                &mut buffer.0,
                (dir_info as *mut DirInfo<D>).cast(),
                &mut status.0,
            ) == 0
            {
                return Err(status.into());
            }
        }
        Ok(())
    }
}

impl Drop for DirBuffer {
    fn drop(&mut self) {
        unsafe {
            FspFileSystemDeleteDirectoryBuffer(&mut self.0);
        }
    }
}

impl Drop for DirBufferLock<'_> {
    fn drop(&mut self) {
        let buffer = &mut self.0;

        unsafe { FspFileSystemReleaseDirectoryBuffer(&mut buffer.0) }
    }
}

#[repr(C)]
union DirInfoPadding {
    next_offset: u64,
    padding: [u8; 24],
}

#[repr(C)]
pub struct DirInfo<const BUFFER_SIZE: usize> {
    size: u16,
    file_info: FSP_FSCTL_FILE_INFO,
    padding: DirInfoPadding,
    file_name: [u16; BUFFER_SIZE],
}

impl<const BUFFER_SIZE: usize> DirInfo<BUFFER_SIZE> {
    pub fn new() -> Self {
        const _: () = assert!(104 == std::mem::size_of::<DirInfo<0>>());
        assert_eq!(
            Layout::new::<FSP_FSCTL_DIR_INFO>(),
            Layout::new::<DirInfo<0>>()
        );
        Self {
            // begin with initially no file_name
            size: std::mem::size_of::<DirInfo<0>>() as u16,
            file_info: FSP_FSCTL_FILE_INFO::default(),
            padding: DirInfoPadding { padding: [0; 24] },
            file_name: [0; BUFFER_SIZE],
        }
    }

    /// Get a mutable reference to the file information of this directory entry.
    pub fn file_info_mut(&mut self) -> &mut FSP_FSCTL_FILE_INFO {
        &mut self.file_info
    }
}

impl<const BUFFER_SIZE: usize> Default for DirInfo<BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BUFFER_SIZE: usize> WideNameInfo<BUFFER_SIZE> for DirInfo<BUFFER_SIZE> {
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE] {
        &mut self.file_name
    }

    fn set_size(&mut self, buffer_size: u16) {
        self.size = std::mem::size_of::<DirInfo<0>>() as u16 + buffer_size
    }

    /// Reset the directory entry.
    fn reset(&mut self) {
        self.size = std::mem::size_of::<DirInfo<0>>() as u16;
        self.file_info = FSP_FSCTL_FILE_INFO::default();
        self.padding.next_offset = 0;
        self.padding.padding = [0; 24];
        self.file_name = [0; BUFFER_SIZE]
    }

    fn add_to_buffer_internal(entry: Option<&Self>, buffer: &mut [u8], cursor: &mut u32) -> bool {
        unsafe {
            // SAFETY: https://github.com/winfsp/winfsp/blob/0a91292e0502d6629f9a968a168c6e89eea69ea1/src/dll/fsop.c#L1500
            // does not mutate entry.
            if let Some(entry) = entry {
                FspFileSystemAddDirInfo(
                    (entry as *const Self).cast_mut().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            } else {
                FspFileSystemAddDirInfo(
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            }
        }
    }
}
