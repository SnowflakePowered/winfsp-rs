use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_OPEN_FILE_INFO};
use crate::constants::FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX;
use crate::filesystem::ensure_layout;

#[repr(C)]
#[derive(Default, Clone, Debug)]
/// A struct that holds information about a file.
pub struct FileInfo {
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub allocation_size: u64,
    pub file_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
    pub hard_links: u32,
    pub ea_size: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
/// A struct that holds information about a file to be opened or created.
///
/// `OpenFileInfo` implements [`AsRef`](core::convert::AsRef) and [`AsMut`](core::convert::AsMut)
/// for [`FileInfo`](crate::filesystem::FileInfo), which should be used to access the fields
/// that store the file information.
///
/// For case-sensitive filesystems,
pub struct OpenFileInfo {
    file_info: FileInfo,
    normalized_name: winfsp_sys::PWSTR,
    /// normalized name length in BYTES.
    normalized_name_len: u16
}

impl OpenFileInfo {
    /// Sets the normalized name of the FileInfo. An optional prefix can be added to ensure that
    /// the prefix is written before the FileName.
    ///
    /// ## Safety
    /// The size of the buffer **in bytes** can not exceed
    /// [`FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX`](crate::constants::FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX) - 1,
    pub fn set_normalized_name(&mut self, name: &[u16], prefix: Option<u16>) {
        let first_letter = name.first().cloned();
        let file_name: &[u8] = bytemuck::cast_slice(name);
        if file_name.len() >= FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX {
            panic!("The file name buffer is too large to fit into the transaction!");
        }

        if let (Some(prefix), false) = (prefix, first_letter == prefix) {
            unsafe {
                self.normalized_name.write(prefix);
                self.normalized_name.map_addr(|addr| addr.wrapping_add(1))
                    .cast::<u8>()
                    .copy_from_nonoverlapping(file_name.as_ptr(), file_name.len());
            }
            self.normalized_name_len = (std::mem::size_of::<u16>() + file_name.len()) as u16;
        } else {
            // either no prefix, or starts with prefix
            unsafe {
                self.normalized_name.cast::<u8>().copy_from_nonoverlapping(file_name.as_ptr(), file_name.len())
            }
            self.normalized_name_len = file_name.len() as u16;
        }
    }

    /// Get the size of the normalized name in bytes.
    /// This starts out as the size of the buffer.
    pub fn normalized_name_size(&self) -> u16 {
        self.normalized_name_len
    }
}

impl AsRef<FileInfo> for OpenFileInfo {
    fn as_ref(&self) -> &FileInfo {
        &self.file_info
    }
}

impl AsMut<FileInfo> for OpenFileInfo {
    fn as_mut(&mut self) -> &mut FileInfo {
        &mut self.file_info
    }
}

ensure_layout!(FSP_FSCTL_FILE_INFO, FileInfo);
ensure_layout!(FSP_FSCTL_OPEN_FILE_INFO, OpenFileInfo);