//! Useful constants re-exported from [`winfsp-sys`](https://docs.rs/winfsp-sys/).
use winfsp_sys::{FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP, WCHAR};

/// Flags passed to [FileSystemContext::cleanup](crate::filesystem::FileSystemContext::cleanup)
#[repr(u32)]
#[derive(Copy, Clone)]
pub enum FspCleanupFlags {
    /// Delete the file.
    FspCleanupDelete = 0x01,
    /// Set the allocation size of the file.
    FspCleanupSetAllocationSize = 0x02,
    /// Set the archive bit of the file.
    FspCleanupSetArchiveBit = 0x10,
    /// Set the last access time for the file.
    FspCleanupSetLastAccessTime = 0x20,
    /// Set the last write time for the file.
    FspCleanupSetLastWriteTime = 0x40,
    /// Set the change time for the file.
    FspCleanupSetChangeTime = 0x80,
}

impl FspCleanupFlags {
    /// Check if the flag is set in the provided bitfield.
    pub fn is_flagged(&self, flag: u32) -> bool {
        (*self as u32) & flag != 0
    }
}

#[repr(u32)]
#[derive(Copy, Clone)]
/// An enumeration of possible transaction kinds by the WinFSP file system driver.
pub enum FspTransactKind {
    /// Reserved.
    FspFsctlTransactReservedKind = 0,
    /// Create
    FspFsctlTransactCreateKind,
    /// Overwrite
    FspFsctlTransactOverwriteKind,
    /// Cleanup
    FspFsctlTransactCleanupKind,
    /// Close
    FspFsctlTransactCloseKind,
    /// Read
    FspFsctlTransactReadKind,
    /// Write
    FspFsctlTransactWriteKind,
    /// QueryInformation
    FspFsctlTransactQueryInformationKind,
    /// SetInformation
    FspFsctlTransactSetInformationKind,
    /// QueryEa
    FspFsctlTransactQueryEaKind,
    /// SetEa
    FspFsctlTransactSetEaKind,
    /// FlushBuffers
    FspFsctlTransactFlushBuffersKind,
    /// QueryVolumeInformation
    FspFsctlTransactQueryVolumeInformationKind,
    /// SetVolumeInformation
    FspFsctlTransactSetVolumeInformationKind,
    /// QueryDirectory
    FspFsctlTransactQueryDirectoryKind,
    /// FileSystemControl
    FspFsctlTransactFileSystemControlKind,
    /// DeviceControl
    FspFsctlTransactDeviceControlKind,
    /// Shutdown
    FspFsctlTransactShutdownKind,
    /// LockControl
    FspFsctlTransactLockControlKind,
    /// QuerySecurity
    FspFsctlTransactQuerySecurityKind,
    /// SetSecurity
    FspFsctlTransactSetSecurityKind,
    /// QueryStreamInformation
    FspFsctlTransactQueryStreamInformationKind,
    /// Maximum valid number of transaction kinds
    FspFsctlTransactKindCount,
}

/// The maximum size of a file path in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_PATH_SIZEMAX: usize = 1024 * std::mem::size_of::<WCHAR>();

/// The maximum size of a request buffer in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_REQ_BUFFER_SIZEMAX: usize =
    FSP_FSCTL_TRANSACT_REQ_SIZEMAX - std::mem::size_of::<FSP_FSCTL_TRANSACT_REQ>();

/// The maximum size of a response buffer in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX: usize =
    FSP_FSCTL_TRANSACT_RSP_SIZEMAX - std::mem::size_of::<FSP_FSCTL_TRANSACT_RSP>();

/// The default alignment for WinFSP structs.
pub const FSP_FSCTL_DEFAULT_ALIGNMENT: usize = winfsp_sys::FSP_FSCTL_DEFAULT_ALIGNMENT as usize;

/// The maximum size of a device control buffer.
pub const FSP_FSCTL_DEVICECONTROL_SIZEMAX: usize =
    winfsp_sys::FSP_FSCTL_DEVICECONTROL_SIZEMAX as usize;

/// The minimum size of a transaction buffer in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_BUFFER_SIZEMIN: usize =
    winfsp_sys::FSP_FSCTL_TRANSACT_BUFFER_SIZEMIN as usize;

/// The minimum size of a request buffer in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_REQ_SIZEMAX: usize =
    winfsp_sys::FSP_FSCTL_TRANSACT_REQ_SIZEMAX as usize;

/// The minimum size of a response buffer in a WinFSP transaction.
pub const FSP_FSCTL_TRANSACT_RSP_SIZEMAX: usize =
    winfsp_sys::FSP_FSCTL_TRANSACT_RSP_SIZEMAX as usize;

/// The maximum length of a path.
pub const MAX_PATH: usize = 260;
