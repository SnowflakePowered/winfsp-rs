use crate::filesystem::{ensure_layout, WideNameInfo};
use winfsp_sys::{FspFileSystemAddNotifyInfo, FSP_FSCTL_NOTIFY_INFO};

#[repr(C)]
#[derive(Debug, Clone)]
/// Information about a filesystem event.
pub struct NotifyInfo<const BUFFER_SIZE: usize = 255> {
    pub(crate) size: u16,
    pub filter: u32,
    pub action: u32,
    file_name: [u16; BUFFER_SIZE],
}

ensure_layout!(FSP_FSCTL_NOTIFY_INFO, NotifyInfo<0>);
impl<const BUFFER_SIZE: usize> NotifyInfo<BUFFER_SIZE> {
    pub fn new() -> Self {
        Self {
            // begin with initially no file_name
            size: std::mem::size_of::<NotifyInfo<0>>() as u16,
            filter: 0,
            action: 0,
            file_name: [0; BUFFER_SIZE],
        }
    }
}

impl<const BUFFER_SIZE: usize> Default for NotifyInfo<BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BUFFER_SIZE: usize> WideNameInfo<BUFFER_SIZE> for NotifyInfo<BUFFER_SIZE> {
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE] {
        &mut self.file_name
    }

    fn set_size(&mut self, buffer_size: u16) {
        self.size = std::mem::size_of::<NotifyInfo<0>>() as u16 + buffer_size;
    }

    fn reset(&mut self) {
        self.size = std::mem::size_of::<NotifyInfo<0>>() as u16;
        self.filter = 0;
        self.action = 0;
        self.file_name = [0; BUFFER_SIZE];
    }

    fn add_to_buffer_internal(entry: Option<&Self>, buffer: &mut [u8], cursor: &mut u32) -> bool {
        unsafe {
            // SAFETY: https://github.com/winfsp/winfsp/blob/0a91292e0502d6629f9a968a168c6e89eea69ea1/src/dll/fsop.c#L1500
            // does not mutate entry.
            if let Some(entry) = entry {
                FspFileSystemAddNotifyInfo(
                    (entry as *const Self).cast_mut().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            } else {
                FspFileSystemAddNotifyInfo(
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    cursor,
                ) != 0
            }
        }
    }
}
