use std::cell::RefCell;
use std::ops::Deref;
use std::sync::Arc;
use parking_lot::RwLock;
use windows::Win32::Foundation::HANDLE;
use winfsp::filesystem::DirBuffer;
use winfsp::util::{NtSafeHandle, NtRefHandle};

#[derive(Debug)]
pub struct NtPassthroughFile {
    handle: Arc<RwLock<NtSafeHandle>>,
    is_directory: bool,
    dir_buffer: DirBuffer,
    file_size_hint: u64,
}

impl NtPassthroughFile {
    pub fn new(handle: NtSafeHandle, file_size_hint: u64, is_directory: bool) -> Self {
        Self {
            handle: Arc::new(RwLock::new(handle)),
            file_size_hint,
            is_directory,
            dir_buffer: DirBuffer::new(),
        }
    }

    pub fn handle(&self) -> HANDLE {
        *(self.handle).read().deref().deref()
    }

    pub fn invalidate(&self) {
        self.handle.write().invalidate()
    }

    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    pub fn dir_size(&self) -> u32 {
        self.file_size_hint as u32
    }

    pub fn dir_buffer(&self) -> &DirBuffer {
        &self.dir_buffer
    }

    /// Explicitly invalidate the handle before drop.
    pub fn close(self) {
        self.invalidate();
        drop(self)
    }
}