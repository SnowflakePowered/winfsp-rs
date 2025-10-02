use crate::constants::FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX;
use crate::filesystem::ensure_layout;
use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_OPEN_FILE_INFO};

#[repr(C)]
#[derive(Default, Clone, Debug)]
/// A struct that holds information about a file.
pub struct FileInfo {
    /// Specifies one or more FILE_ATTRIBUTE_XXX flags. For descriptions of these flags,
    /// see [File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants) in the Microsoft Windows SDK.
    pub file_attributes: u32,
    /// Specifies the reparse point tag. If the `file_attributes` member includes the FILE_ATTRIBUTE_REPARSE_POINT attribute flag,
    /// this member specifies the reparse tag. Otherwise, this member is unused.
    pub reparse_tag: u32,
    /// The file allocation size in bytes. Usually, this value is a multiple of the sector or cluster size of the underlying physical device.
    pub allocation_size: u64,
    /// The end of file location as a byte offset.
    pub file_size: u64,
    /// Specifies the time that the file was created.
    pub creation_time: u64,
    /// Specifies the time that the file was last accessed.
    pub last_access_time: u64,
    /// Specifies the time that the file was last written to.
    pub last_write_time: u64,
    /// Specifies the last time the file was changed.
    pub change_time: u64,
    /// The 8-byte file reference number for the file. This number is assigned by the file system and is file-system-specific.
    /// (Note that this is not the same as the 16-byte "file object ID" that was added to NTFS for Microsoft Windows 2000.)
    pub index_number: u64,
    /// The number of hard links to the file. This is unimplemented in WinFSP and should always be 0.
    pub hard_links: u32,
    /// Specifies the combined length, in bytes, of the extended attributes for the file.
    pub ea_size: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
/// A struct that holds information about a file to be opened or created.
///
/// `OpenFileInfo` implements [`AsRef`](core::convert::AsRef) and [`AsMut`](core::convert::AsMut)
/// for [`FileInfo`](crate::filesystem::FileInfo), which should be used to access the fields
/// that store the file information.
pub struct OpenFileInfo {
    file_info: FileInfo,
    normalized_name: winfsp_sys::PWSTR,
    /// normalized name length in BYTES.
    normalized_name_len: u16,
}

impl OpenFileInfo {
    /// Sets the normalized name of the FileInfo. An optional prefix can be added to ensure that
    /// the prefix is written before the FileName.
    ///
    /// For case-sensitive filesystems, this functionality should be ignored. WinFSP will always assume
    /// that the normalized file name is the same as the file name used to open the file.
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

                self.normalized_name
                    .map_addr(|addr| addr.wrapping_add(1))
                    .cast::<u8>()
                    .copy_from_nonoverlapping(file_name.as_ptr(), file_name.len());
            }
            self.normalized_name_len = (std::mem::size_of::<u16>() + file_name.len()) as u16;
        } else {
            // either no prefix, or starts with prefix
            unsafe {
                self.normalized_name
                    .cast::<u8>()
                    .copy_from_nonoverlapping(file_name.as_ptr(), file_name.len())
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
