use crate::filesystem::{ensure_layout, WideNameInfo};
use winfsp_sys::{FspFileSystemAddStreamInfo, FSP_FSCTL_STREAM_INFO};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct StreamInfo<const BUFFER_SIZE: usize = 255> {
    size: u16,
    pub stream_size: u64,
    pub stream_alloc_size: u64,
    stream_name: [u16; BUFFER_SIZE],
}

ensure_layout!(FSP_FSCTL_STREAM_INFO, StreamInfo<0>);
impl<const BUFFER_SIZE: usize> StreamInfo<BUFFER_SIZE> {
    pub fn new() -> Self {
        Self {
            // begin with initially no file_name
            size: std::mem::size_of::<StreamInfo<0>>() as u16,
            stream_size: 0,
            stream_alloc_size: 0,
            stream_name: [0; BUFFER_SIZE],
        }
    }
}

impl<const BUFFER_SIZE: usize> Default for StreamInfo<BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BUFFER_SIZE: usize> WideNameInfo<BUFFER_SIZE> for StreamInfo<BUFFER_SIZE> {
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE] {
        &mut self.stream_name
    }

    fn set_size(&mut self, buffer_size: u16) {
        self.size = std::mem::size_of::<StreamInfo<0>>() as u16 + buffer_size;
    }

    fn reset(&mut self) {
        self.size = std::mem::size_of::<StreamInfo<0>>() as u16;
        self.stream_size = 0;
        self.stream_alloc_size = 0;
        self.stream_name = [0; BUFFER_SIZE];
    }

    fn add_to_buffer_internal(entry: Option<&Self>, buffer: &mut [u8], cursor: &mut u32) -> bool {
        unsafe {
            // SAFETY: https://github.com/winfsp/winfsp/blob/0a91292e0502d6629f9a968a168c6e89eea69ea1/src/dll/fsop.c#L1500
            // does not mutate entry.
            if let Some(entry) = entry {
                FspFileSystemAddStreamInfo(
                    (entry as *const Self).cast_mut().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            } else {
                FspFileSystemAddStreamInfo(
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            }
        }
    }
}
