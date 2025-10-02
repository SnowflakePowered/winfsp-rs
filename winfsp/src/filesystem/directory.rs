use std::cell::UnsafeCell;
use widestring::{U16CStr, u16cstr};
use windows::Win32::Foundation::STATUS_SUCCESS;
use winfsp_sys::{
    FSP_FSCTL_DIR_INFO, FspFileSystemAcquireDirectoryBufferEx, FspFileSystemAddDirInfo,
    FspFileSystemDeleteDirectoryBuffer, FspFileSystemFillDirectoryBuffer,
    FspFileSystemReadDirectoryBuffer, FspFileSystemReleaseDirectoryBuffer, PVOID,
};

use crate::error::Result;
use crate::filesystem::sealed::WideNameInfoInternal;
use crate::filesystem::{FileInfo, WideNameInfo, ensure_layout};
use crate::util::AssertThreadSafe;

/// A buffer used to hold directory entries when enumerating directories
/// with the [`read_directory`](crate::filesystem::FileSystemContext::read_directory)
/// callback.
///
/// DirBuffer provides interior mutability for the directory buffer, which is
/// managed completely by the filesystem driver. This is because the filesystem
/// driver may create multiple threads that could possibly run afoul of the
/// aliasing rules of `&mut`.
#[derive(Debug)]
pub struct DirBuffer(AssertThreadSafe<UnsafeCell<PVOID>>);
/// A lock into the directory read buffer that must be held while writing, and dropped
/// as soon as writing of directory entries into the buffer is complete.
#[derive(Debug)]
pub struct DirBufferLock<'a>(&'a DirBuffer);
/// A marker into the current position of the directory file when
/// enumerating directories with [`read_directory`](crate::filesystem::FileSystemContext::read_directory)
#[derive(Debug)]
pub struct DirMarker<'a>(pub(crate) Option<&'a U16CStr>);

impl DirMarker<'_> {
    /// Reset the marker.
    pub fn reset(&mut self) {
        self.0.take();
    }

    /// Returns whether this marker exists.
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    /// Returns whether this marker is the parent directory '..'.
    pub fn is_parent(&self) -> bool {
        if let Some(marker) = self.0 {
            return marker == u16cstr!("..");
        }
        false
    }

    /// Returns whether this marker is the current directory '.'.
    pub fn is_current(&self) -> bool {
        if let Some(marker) = self.0 {
            return marker == u16cstr!(".");
        }
        false
    }

    /// Returns the inner contents of the marker.
    /// If the inner contents were not validly null-terminated, returns None.
    pub fn inner(&self) -> Option<&[u16]> {
        self.0.map(U16CStr::as_slice)
    }

    /// Returns the inner contents of the marker.
    /// If the inner contents were not validly null-terminated, returns None.
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
    /// Create a new unacquired directory buffer.
    pub fn new() -> Self {
        Self(AssertThreadSafe(UnsafeCell::new(std::ptr::null_mut())))
    }

    /// Try to acquire a lock on the directory buffer to write entries into.
    pub fn acquire(&self, reset: bool, capacity_hint: Option<u32>) -> Result<DirBufferLock<'_>> {
        let mut result = STATUS_SUCCESS;
        unsafe {
            if FspFileSystemAcquireDirectoryBufferEx(
                self.0.0.get(),
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

    /// Read the contents of the directory buffer into the provided slice,
    /// returning the number of bytes written.
    ///
    /// If the directory buffer was never acquired, this is a no-op.
    pub fn read(&self, marker: DirMarker, buffer: &mut [u8]) -> u32 {
        let mut out = 0u32;
        unsafe {
            FspFileSystemReadDirectoryBuffer(
                self.0.0.get(),
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
    /// Write a directory entry into the directory buffer.
    ///
    /// A buffer can accept multiple DirInfos of varying sizes.
    pub fn write<const D: usize>(&self, dir_info: &mut DirInfo<D>) -> Result<()> {
        let mut status = STATUS_SUCCESS;
        unsafe {
            let buffer = self.0;
            // this is cursed.
            if FspFileSystemFillDirectoryBuffer(
                buffer.0.0.get(),
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
            FspFileSystemDeleteDirectoryBuffer(self.0.0.get());
        }
    }
}

impl Drop for DirBufferLock<'_> {
    fn drop(&mut self) {
        let buffer = self.0;
        unsafe { FspFileSystemReleaseDirectoryBuffer(buffer.0.0.get()) }
    }
}

#[repr(C)]
union DirInfoPadding {
    next_offset: u64,
    padding: [u8; 24],
}

#[repr(C)]
/// A directory information entry.
///
/// ## Safety
/// Note that `BUFFER_SIZE` is the size of the name buffer in characters, not bytes.
/// In most cases, the default is sufficient. A buffer size that is too large
/// may not be copyable to the request buffer.
pub struct DirInfo<const BUFFER_SIZE: usize = 255> {
    size: u16,
    file_info: FileInfo,
    padding: DirInfoPadding,
    file_name: [u16; BUFFER_SIZE],
}

ensure_layout!(FSP_FSCTL_DIR_INFO, DirInfo<0>);
impl<const BUFFER_SIZE: usize> DirInfo<BUFFER_SIZE> {
    /// Create a new, empty directory entry info.
    pub fn new() -> Self {
        Self {
            // begin with initially no file_name
            size: std::mem::size_of::<DirInfo<0>>() as u16,
            file_info: FileInfo::default(),
            padding: DirInfoPadding { padding: [0; 24] },
            file_name: [0; BUFFER_SIZE],
        }
    }

    /// Get a mutable reference to the file information of this directory entry.
    pub fn file_info_mut(&mut self) -> &mut FileInfo {
        &mut self.file_info
    }
}

impl<const BUFFER_SIZE: usize> Default for DirInfo<BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BUFFER_SIZE: usize> WideNameInfoInternal<BUFFER_SIZE> for DirInfo<BUFFER_SIZE> {
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE] {
        &mut self.file_name
    }

    fn set_size(&mut self, buffer_size: u16) {
        self.size = std::mem::size_of::<DirInfo<0>>() as u16 + buffer_size
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

impl<const BUFFER_SIZE: usize> WideNameInfo<BUFFER_SIZE> for DirInfo<BUFFER_SIZE> {
    /// Reset the directory entry.
    fn reset(&mut self) {
        self.size = std::mem::size_of::<DirInfo<0>>() as u16;
        self.file_info = FileInfo::default();
        self.padding.next_offset = 0;
        self.padding.padding = [0; 24];
        self.file_name = [0; BUFFER_SIZE]
    }
}
