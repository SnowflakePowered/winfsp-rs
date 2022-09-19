use windows::Win32::Foundation::HANDLE;
use winfsp::filesystem::DirBuffer;
use winfsp::util::NtSafeHandle;

#[derive(Debug)]
pub struct NtPassthroughFile {
    handle: NtSafeHandle,
    is_directory: bool,
    dir_buffer: DirBuffer,
    file_size_hint: u64,
}

impl NtPassthroughFile {
    pub fn new(handle: NtSafeHandle, file_size_hint: u64, is_directory: bool) -> Self {
        Self {
            handle,
            file_size_hint,
            is_directory,
            dir_buffer: DirBuffer::new(),
        }
    }

    pub fn handle(&self) -> HANDLE {
        *self.handle
    }

    pub fn invalidate(&mut self) {
        self.handle.invalidate()
    }

    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    pub fn dir_size(&self) -> u32 {
        self.file_size_hint as u32
    }

    pub fn dir_buffer(&mut self) -> &mut DirBuffer {
        &mut self.dir_buffer
    }

    /// Explicitly invalidate the handle before drop.
    pub fn close(mut self) {
        self.handle.invalidate();
        drop(self)
    }
}
