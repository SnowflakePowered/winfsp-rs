use windows::Win32::Foundation::HANDLE;
use winfsp::filesystem::DirBuffer;
use winfsp::util::NtSafeHandle;

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
}
