use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::w;
use winfsp_sys::FSP_FSCTL_VOLUME_PARAMS;

#[repr(transparent)]
#[derive(Debug, Clone)]
/// Parameters that control how the WinFSP volume is mounted and processes requests.
pub struct VolumeParams(pub(crate) FSP_FSCTL_VOLUME_PARAMS);

/// Sets whether the FileContext represents a file node, or a file descriptor.
///
/// A file node uniquely identifies an open file, and opening the same file name should always yield
/// the same file node value for as long as the file with that name remains open anywhere in the system.
///
/// A file descriptor identifies an open instance of a file. Opening the same file name may yield
/// a different file descriptor. This is WinFSP's `UmFileContextIsUserContext2` mode.
///
/// WinFSP's `UmFileContextIsFullContext` mode is not supported.
pub enum FileContextMode {
    #[deprecated = "FileContextMode::Node is unsound."]
    /// The file context is a node, and opening the same file name will always yield the same value.
    Node,
    /// The file context is a descriptor, and opening the same file name may yield a different value.
    Descriptor,
}

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
impl VolumeParams {
    pub fn new(mode: FileContextMode) -> Self {
        let mut params = FSP_FSCTL_VOLUME_PARAMS::default();

        match mode {
            FileContextMode::Node => {
                panic!("FileContextMode::Node is unsound.")
            }
            FileContextMode::Descriptor => {
                params.set_UmFileContextIsFullContext(0);
                params.set_UmFileContextIsUserContext2(1);
            }
        }
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

    pub fn prefix<P: AsRef<OsStr>>(&mut self, prefix: P) -> &mut Self {
        let prefix = prefix.as_ref();
        let prefix: Vec<u16> = prefix.encode_wide().collect();
        self.0.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix[..std::cmp::min(prefix.len(), 192)]);
        self
    }

    pub fn filesystem_name<P: AsRef<OsStr>>(&mut self, filesystem_name: P) -> &mut Self {
        let filesystem_name = filesystem_name.as_ref();
        let filesystem_name: Vec<u16> = filesystem_name.encode_wide().collect();
        self.0.FileSystemName[..std::cmp::min(filesystem_name.len(), 192)]
            .copy_from_slice(&filesystem_name[..std::cmp::min(filesystem_name.len(), 192)]);
        self
    }

    make_setters! {
        sectors_per_allocation_unit = SectorsPerAllocationUnit: u16;
        sector_size = SectorSize: u16;
        max_component_length = MaxComponentLength: u16;
        volume_creation_time = VolumeCreationTime: u64;
        volume_serial_number = VolumeSerialNumber: u32;
        transact_timeout = TransactTimeout: u32;
        irp_timeout = IrpTimeout: u32;
        irp_capacity = IrpCapacity: u32;
        file_info_timeout = FileInfoTimeout: u32;
        dir_info_timeout = DirInfoTimeout: u32;
        volume_info_timeout = VolumeInfoTimeout: u32;
        security_timeout = SecurityTimeout: u32;
        stream_info_timeout = StreamInfoTimeout: u32;
        extended_attribute_timeout = EaTimeout: u32;
        fsext_control_code = FsextControlCode: u32;
    }

    make_setters! {
        case_sensitive_search = CaseSensitiveSearch;
        case_preserved_names = CasePreservedNames;
        unicode_on_disk = UnicodeOnDisk;
        persistent_acls = PersistentAcls;
        reparse_points = ReparsePoints;
        reparse_points_access_check = ReparsePointsAccessCheck;
        named_streams = NamedStreams;
        hard_links = HardLinks;
        extended_attributes = ExtendedAttributes;
        read_only_volume = ReadOnlyVolume;
        post_cleanup_when_modified_only = PostCleanupWhenModifiedOnly;
        flush_and_purge_on_cleanup = FlushAndPurgeOnCleanup;
        pass_query_directory_pattern = PassQueryDirectoryPattern;
        /// Pass the filename when querying directory.
        /// Enabling is required to use `get_dirinfo_by_name`.
        pass_query_directory_filename = PassQueryDirectoryFileName;
        always_use_double_buffering = AlwaysUseDoubleBuffering;
        device_control = DeviceControl;
        no_reparse_points_dir_check = UmNoReparsePointsDirCheck;
        allow_open_in_kernel_mode = AllowOpenInKernelMode;
        case_preseve_extended_attributes = CasePreservedExtendedAttributes;
        wsl_features = WslFeatures;
        directory_marker_as_next_offset = DirectoryMarkerAsNextOffset;
        supports_posix_unlink_rename = SupportsPosixUnlinkRename;
        post_disposition_only_when_necessary = PostDispositionWhenNecessaryOnly;
    }
}
