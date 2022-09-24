use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winfsp_sys::FSP_FSCTL_VOLUME_INFO;
use crate::filesystem::ensure_layout;

#[repr(C)]
pub struct VolumeInfo {
    pub total_size: u64,
    pub free_size: u64,
    volume_label_length: u16,
    volume_label: [u16; 32]
}

ensure_layout!(FSP_FSCTL_VOLUME_INFO, VolumeInfo);
impl VolumeInfo {
    pub fn set_volume_label<P: AsRef<OsStr>>(&mut self, volume_label: P) -> &mut Self {
        let volume_label = volume_label.as_ref();
        let volume_label: Vec<u16> = volume_label.encode_wide().collect();

        let max_len = std::cmp::min(self.volume_label.len(), volume_label.len());
        self.volume_label[0..max_len].copy_from_slice(&volume_label[0..max_len]);
        // safety: max_len is less than 32.
        self.volume_label_length = (max_len * std::mem::size_of::<u16>()) as u16;
        self
    }
}
