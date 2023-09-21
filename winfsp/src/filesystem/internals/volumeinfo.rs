use crate::filesystem::ensure_layout;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winfsp_sys::FSP_FSCTL_VOLUME_INFO;

/// A struct that holds information about the volume.
#[repr(C)]
pub struct VolumeInfo {
    /// The total size of the volume.
    pub total_size: u64,
    /// The free size remaining in the volume.
    pub free_size: u64,
    volume_label_length: u16,
    volume_label: [u16; 32],
}

ensure_layout!(FSP_FSCTL_VOLUME_INFO, VolumeInfo);
impl VolumeInfo {
    /// Set the volume label for this `VolumeInfo`.
    ///
    /// A `VolumeInfo` can only hold up to 32 characters. A label longer than 32 characters
    /// will be truncated.
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
