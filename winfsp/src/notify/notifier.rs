use crate::notify::NotifyInfo;
use winfsp_sys::{FSP_FILE_SYSTEM, FspFileSystemNotify};

/// A notifier used to notify the filesystem of changes.
pub struct Notifier(pub(crate) *mut FSP_FILE_SYSTEM);
impl Notifier {
    /// Notify the filesystem of the given change event.
    pub fn notify<const BUFFER_SIZE: usize>(&self, info: &NotifyInfo<BUFFER_SIZE>) {
        unsafe {
            FspFileSystemNotify(
                self.0,
                // SAFETY: FspFileSystemNotify calls DeviceIoControl with the buffer specified as [in].
                (info as *const NotifyInfo<BUFFER_SIZE>).cast_mut().cast(),
                info.size as u64,
            )
        };
    }
}
