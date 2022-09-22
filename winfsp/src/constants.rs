//! Useful constants re-exported from `winfsp-sys`.
use winfsp_sys::{FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP, WCHAR};

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum FspCleanupFlags {
    FspCleanupDelete = 0x01,
    FspCleanupSetAllocationSize = 0x02,
    FspCleanupSetArchiveBit = 0x10,
    FspCleanupSetLastAccessTime = 0x20,
    FspCleanupSetLastWriteTime = 0x40,
    FspCleanupSetChangeTime = 0x80,
}

impl FspCleanupFlags {
    /// Check if the provided bitfield has a flag.
    pub fn is_flagged(&self, flag: u32) -> bool {
        (*self as u32) & flag != 0
    }
}
pub const FSP_FSCTL_TRANSACT_PATH_SIZEMAX: usize = 1024 * std::mem::size_of::<WCHAR>();
pub const FSP_FSCTL_TRANSACT_REQ_BUFFER_SIZEMAX: usize =
    FSP_FSCTL_TRANSACT_REQ_SIZEMAX as usize - std::mem::size_of::<FSP_FSCTL_TRANSACT_REQ>();
pub const FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX: usize =
    FSP_FSCTL_TRANSACT_RSP_SIZEMAX as usize - std::mem::size_of::<FSP_FSCTL_TRANSACT_RSP>();

pub const FSP_FSCTL_DEFAULT_ALIGNMENT: usize = winfsp_sys::FSP_FSCTL_DEFAULT_ALIGNMENT as usize;
pub const FSP_FSCTL_DEVICECONTROL_SIZEMAX: usize = winfsp_sys::FSP_FSCTL_DEVICECONTROL_SIZEMAX as usize;
pub const FSP_FSCTL_TRANSACT_BATCH_BUFFER_SIZEMIN: usize = winfsp_sys::FSP_FSCTL_TRANSACT_BATCH_BUFFER_SIZEMIN as usize;
pub const FSP_FSCTL_TRANSACT_BUFFER_SIZEMIN: usize = winfsp_sys::FSP_FSCTL_TRANSACT_BUFFER_SIZEMIN as usize;
pub const FSP_FSCTL_TRANSACT_REQ_SIZEMAX: usize = winfsp_sys::FSP_FSCTL_TRANSACT_REQ_SIZEMAX as usize;
pub const FSP_FSCTL_TRANSACT_RSP_SIZEMAX: usize = winfsp_sys::FSP_FSCTL_TRANSACT_RSP_SIZEMAX as usize;
