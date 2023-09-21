use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::w;
use winfsp_sys::FSP_FSCTL_VOLUME_PARAMS;

#[repr(transparent)]
#[derive(Debug, Clone)]
/// Parameters that control how the WinFSP volume is mounted and processes requests.
pub struct VolumeParams(pub(crate) FSP_FSCTL_VOLUME_PARAMS);

macro_rules! make_setters {
    (
        $(
            $(#[$outer:meta])*
            $name: ident = $ffi_name:ident: $ty:ty;
        )+
    ) => {
        $(
            $(#[$outer])*
            pub fn $name(&mut self, n: $ty) -> &mut Self {
                self.0.$ffi_name = n;
                self
            }
        )+
    };
    (
        $(
            $(#[$outer:meta])*
            $name: ident = $ffi_name:ident;
        )+
    ) => {
        $(
            $(#[$outer])*
            pub fn $name(&mut self, n: bool) -> &mut Self {
                paste::paste! {
                    self.0.[<set_ $ffi_name>](if n { 1 } else { 0 });
                }
                self
            }
        )+
    };
}

impl Default for VolumeParams {
    fn default() -> Self {
        VolumeParams::new()
    }
}

impl VolumeParams {
    /// Create a new `VolumeParams`
    pub fn new() -> Self {
        let mut params = FSP_FSCTL_VOLUME_PARAMS::default();

        // descriptor mode
        params.set_UmFileContextIsFullContext(0);
        params.set_UmFileContextIsUserContext2(1);

        // hard links are unimplemented.
        params.set_HardLinks(0);

        // This is hardcoded, might as well ensure so.
        // See https://github.com/winfsp/winfsp/issues/55
        params.set_AlwaysUseDoubleBuffering(1);
        VolumeParams(params)
    }

    /// Safety: the returned pointer must not be modified.
    pub(crate) unsafe fn get_winfsp_device_name(&self) -> *mut u16 {
        if self.0.Prefix[0] != 0 {
            w!("WinFsp.Net").as_ptr().cast_mut()
        } else {
            w!("WinFsp.Disk").as_ptr().cast_mut()
        }
    }

    /// Set the prefix of the volume.
    pub fn prefix<P: AsRef<OsStr>>(&mut self, prefix: P) -> &mut Self {
        let prefix = prefix.as_ref();
        let prefix: Vec<u16> = prefix.encode_wide().collect();
        self.0.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix[..std::cmp::min(prefix.len(), 192)]);
        self
    }

    /// Set the name of the filesystem.
    pub fn filesystem_name<P: AsRef<OsStr>>(&mut self, filesystem_name: P) -> &mut Self {
        let filesystem_name = filesystem_name.as_ref();
        let filesystem_name: Vec<u16> = filesystem_name.encode_wide().collect();
        self.0.FileSystemName[..std::cmp::min(filesystem_name.len(), 192)]
            .copy_from_slice(&filesystem_name[..std::cmp::min(filesystem_name.len(), 192)]);
        self
    }

    make_setters! {
        /// Set the number of sectors in each allocation unit.
        sectors_per_allocation_unit = SectorsPerAllocationUnit: u16;
        /// Set the size of each sector.
        sector_size = SectorSize: u16;
        /// Set the maximum length of a file name component. A file name component is the portion of a file name between backslashes.
        max_component_length = MaxComponentLength: u16;
        /// Set the time of volume creation.
        volume_creation_time = VolumeCreationTime: u64;
        /// Set the volume serial number.
        volume_serial_number = VolumeSerialNumber: u32;
        /// Set the timeout of a pending IO request packet in milliseconds.
        ///
        /// Supports a a range of 1 minute (60000) to 10 minutes (600000)
        irp_timeout = IrpTimeout: u32;
        /// Set the maximum number of pending IO request packets.
        ///
        /// Supports from 100 packets to 1000 packets.
        irp_capacity = IrpCapacity: u32;
        /// Set the timeout in milliseconds before a FileInfo, or other info request times out.
        ///
        /// Setting this to `u32::MAX` enables the WinFSP cache manager
        file_info_timeout = FileInfoTimeout: u32;
        /// Set the timeout in milliseconds before a DirInfo request times out. Overrides `file_info_timeout`.
        dir_info_timeout = DirInfoTimeout: u32;
        /// Set the timeout in milliseconds before a VolumeInfo request times out. Overrides `file_info_timeout`.
        volume_info_timeout = VolumeInfoTimeout: u32;
        /// Set the timeout in milliseconds before a SecurityInfo request times out. Overrides `file_info_timeout`.
        security_timeout = SecurityTimeout: u32;
        /// Set the timeout in milliseconds before a StreamInfo request times out. Overrides `file_info_timeout`.
        stream_info_timeout = StreamInfoTimeout: u32;
        /// Set the timeout in milliseconds before a ExtendedAttributeInfo request times out. Overrides `file_info_timeout`.
        extended_attribute_timeout = EaTimeout: u32;
        /// Set the `FsextControlCode` for kernel mode drivers. This **must** be set to 0 for user-mode drivers,
        /// and non-zero for kernel-mode drivers.
        ///
        /// See the [WinFSP documentation](https://winfsp.dev/doc/WinFsp-Kernel-Mode-File-Systems/) for more details.
        /// winfsp-rs does not officially support kernel mode filesystems, and until this docstring is updated,
        /// kernel-mode support is exempt from semantic versioning requirements.
        fsext_control_code = FsextControlCode: u32;
    }

    make_setters! {
        /// Set if the file system supports case-sensitive file names.
        case_sensitive_search = CaseSensitiveSearch;
        /// Set if the file system preserves case of file names.
        case_preserved_names = CasePreservedNames;
        /// Set if the file system supports Unicode (i.e. UTF-16) in file names
        unicode_on_disk = UnicodeOnDisk;
        /// Set if the file system preserves and enforces access control lists.
        persistent_acls = PersistentAcls;
        /// Set if the file system supports reparse points.
        reparse_points = ReparsePoints;
        /// Set if the  file system performs reparse point access checks.
        reparse_points_access_check = ReparsePointsAccessCheck;
        /// Set if the file system file system supports named streams.
        named_streams = NamedStreams;
        /// Set if the file system file system supports extended attributes.
        extended_attributes = ExtendedAttributes;
        /// Set if the file system is read only.
        read_only_volume = ReadOnlyVolume;
        /// Set whether or not to post Cleanup when a file was modified/deleted.
        post_cleanup_when_modified_only = PostCleanupWhenModifiedOnly;
        /// Set whether or not to ask the OS to close files as soon as possible.
        flush_and_purge_on_cleanup = FlushAndPurgeOnCleanup;
        /// Set whether to pass Pattern during when querying directories.
        pass_query_directory_pattern = PassQueryDirectoryPattern;
        /// Set whether to pass the filename when querying directory, as opposed to the
        /// search pattern.
        ///
        /// Enabling is required to use `get_dirinfo_by_name`.
        pass_query_directory_filename = PassQueryDirectoryFileName;
        /// Set whether or not to enable user-mode IOCTL handling.
        device_control = DeviceControl;
        /// Set whether to allow opening parse points regardless of the FILE_DIRECTORY_FILE / FILE_NON_DIRECTORY_FILE.
        /// This is needed for FUSE filesystems.
        no_reparse_points_dir_check = UmNoReparsePointsDirCheck;
        /// Set whether to allow the kernel mode driver to open files where possible.
        allow_open_in_kernel_mode = AllowOpenInKernelMode;
        /// Set whether to preserve the case of extended attributes. The default is UPPERCASE.
        case_preseve_extended_attributes = CasePreservedExtendedAttributes;
        /// Set whether or not to support features required for Windows Subsystem for Linux v1.
        wsl_features = WslFeatures;
        /// Set if the directory marker is the next offset instead of the last file name.
        directory_marker_as_next_offset = DirectoryMarkerAsNextOffset;
        /// Set if the file system supports POSIX-style unlink and rename.
        supports_posix_unlink_rename = SupportsPosixUnlinkRename;
        /// Set whether to check if the item to be disposed is a directory or has READONLY attribute
        /// before posting post Disposition.
        post_disposition_only_when_necessary = PostDispositionWhenNecessaryOnly;
    }
}
