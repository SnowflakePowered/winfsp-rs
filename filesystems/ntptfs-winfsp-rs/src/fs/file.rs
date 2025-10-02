use windows::Win32::Foundation::HANDLE;
use winfsp::filesystem::DirBuffer;

use winfsp::util::{AtomicHandle, NtHandleDrop, NtSafeHandle};

/// A file context in the passthrough file system.
#[derive(Debug)]
pub struct NtPassthroughFile {
    handle: AtomicHandle<NtHandleDrop>,
    is_directory: bool,
    dir_buffer: DirBuffer,
    file_size_hint: u64,
}

impl NtPassthroughFile {
    /// Create a new entry from an NT handle.
    pub fn new(handle: NtSafeHandle, file_size_hint: u64, is_directory: bool) -> Self {
        Self {
            handle: handle.into(),
            file_size_hint,
            is_directory,
            dir_buffer: DirBuffer::new(),
        }
    }

    /// Get a HANDLE to this file entry.
    pub fn handle(&self) -> HANDLE {
        HANDLE(self.handle.handle())
    }

    pub fn handle_ref(&self) -> &AtomicHandle<NtHandleDrop> {
        &self.handle
    }

    /// Invalidate the underlying handle for this file entry.
    pub fn invalidate(&self) {
        self.handle.invalidate()
    }

    /// Whether or not this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// The size of the file in bytes.
    pub fn size(&self) -> u32 {
        self.file_size_hint as u32
    }

    /// Get a reference to the directory buffer for this entry.
    pub fn dir_buffer(&self) -> &DirBuffer {
        &self.dir_buffer
    }

    /// Explicitly invalidate the handle before drop.
    pub fn close(self) {
        self.invalidate();
        drop(self)
    }
}
