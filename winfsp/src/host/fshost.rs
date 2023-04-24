use std::cell::UnsafeCell;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::ptr::NonNull;
use windows::core::Result;
use windows::core::HSTRING;
use windows::Win32::Foundation::NTSTATUS;

use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemRemoveMountPoint, FspFileSystemSetMountPoint,
    FspFileSystemSetOperationGuardStrategyF, FspFileSystemStartDispatcher,
    FspFileSystemStopDispatcher, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE,
};

use crate::filesystem::FileSystemContext;
use crate::host::interface::Interface;
use crate::host::{DebugMode, VolumeParams};

#[cfg(feature = "notify")]
use crate::notify::{NotifyingFileSystemContext, Timer};

/// The usermode file system locking strategy.
pub enum OperationGuardStrategy {
    /// A fine-grained concurrency model where file system NAMESPACE accesses are guarded using an exclusive-shared (read-write) lock.
    /// File I/O is not guarded and concurrent reads/writes/etc. are possible.
    /// Note that the FSD will still apply an exclusive-shared lock PER INDIVIDUAL FILE, but it will not limit I/O operations for different files.
    /// The fine-grained concurrency model applies the exclusive-shared lock as follows:
    /// * EXCL: `set_volume_label`, `flush(None)`, `create`, `cleanup` (delete), `rename`
    /// * SHRD: `get_volume_info`, `open`, `set_delete`, `read_directory`
    /// * NONE:  all other operations
    Fine,
    /// A coarse-grained concurrency model where all file system accesses are guarded by a mutually exclusive lock.
    Coarse,
}

/// Options to create the filesystem with.
pub struct FileSystemParams {
    /// Enable the file system driver to call [`FileSystemContext::get_dir_info_by_name`](crate::filesystem::FileSystemContext::get_dir_info_by_name).
    pub use_dir_info_by_name: bool,
    /// The parameters to mount the volume with.
    pub volume_params: VolumeParams,
    /// The usermode file system locking strategy to use.
    pub guard_strategy: OperationGuardStrategy,
    /// Set the debug output mask. Debug output is only displayed if the
    /// `debug` crate feature is enabled, regardless of the mask.
    ///
    /// See [`FspTransactKind`](crate::constants::FspTransactKind) for possible mask values.
    pub debug_mode: DebugMode,
}

impl FileSystemParams {
    /// Use the default options with the given volume parameters.
    pub fn default_params(volume_params: VolumeParams) -> Self {
        Self {
            use_dir_info_by_name: false,
            volume_params,
            guard_strategy: OperationGuardStrategy::Fine,
            debug_mode: Default::default(),
        }
    }

    /// Use the default options with the given volume parameters and debug mode.
    pub fn default_params_debug(volume_params: VolumeParams, debug_mode: DebugMode) -> Self {
        Self {
            use_dir_info_by_name: false,
            volume_params,
            guard_strategy: OperationGuardStrategy::Fine,
            debug_mode,
        }
    }
}
/// The user-mode filesystem host that manages the lifetime of the mounted filesystem.
///
/// This is separate from the lifetime of the service which is managed by
/// [`FileSystemService`](crate::service::FileSystemService). A `FileSystemHost`
/// should start within the context of a service.
pub struct FileSystemHost<'ctx>(
    NonNull<FSP_FILE_SYSTEM>,
    #[cfg(feature = "notify")] Option<Timer>,
    PhantomData<&'ctx FSP_FILE_SYSTEM>,
);
impl<'ctx> FileSystemHost<'ctx> {
    fn new_filesystem_inner<T: FileSystemContext + 'ctx>(
        options: FileSystemParams,
        context: T,
    ) -> Result<NonNull<FSP_FILE_SYSTEM>> {
        #[allow(unused_variables)]
        let FileSystemParams {
            use_dir_info_by_name,
            volume_params,
            guard_strategy,
            debug_mode,
        } = options;

        let mut fsp_struct = std::ptr::null_mut();

        let interface = if use_dir_info_by_name {
            Interface::create_with_dirinfo_by_name::<T>()
        } else {
            Interface::create_with_read_directory::<T>()
        };

        let interface: FSP_FILE_SYSTEM_INTERFACE = interface.into();
        let interface = Box::into_raw(Box::new(UnsafeCell::new(interface)));
        // SAFETY: WinFSP owns the allocation that fsp_struct points to.
        let result = unsafe {
            FspFileSystemCreate(
                volume_params.get_winfsp_device_name(),
                &volume_params.0,
                // SAFETY: UnsafeCell<T> and T are transmutable.
                interface.cast(),
                &mut fsp_struct,
            )
        };

        let result = NTSTATUS(result);
        result.ok()?;

        #[cfg(feature = "debug")]
        unsafe {
            use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
            // pointer crimes
            winfsp_sys::FspDebugLogSetHandle(
                GetStdHandle(STD_ERROR_HANDLE).unwrap().0 as *mut std::ffi::c_void,
            );
            winfsp_sys::FspFileSystemSetDebugLogF(fsp_struct, debug_mode.into());
        }

        unsafe {
            (*fsp_struct).UserContext = Box::into_raw(Box::new(UnsafeCell::new(context))) as *mut _;

            match guard_strategy {
                OperationGuardStrategy::Fine => FspFileSystemSetOperationGuardStrategyF(fsp_struct, FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE),
                OperationGuardStrategy::Coarse => FspFileSystemSetOperationGuardStrategyF(fsp_struct, FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE),
            }
        }

        assert!(!fsp_struct.is_null());
        Ok(NonNull::new(fsp_struct).expect("FSP_FILE_SYSTEM pointer was created but was null!"))
    }

    /// Create a `FileSystemHost` with the default settings
    /// for the provided context implementation.
    pub fn new<T: FileSystemContext + 'ctx>(
        volume_params: VolumeParams,
        context: T,
    ) -> Result<Self> {
        Self::new_with_options::<T>(
            FileSystemParams {
                use_dir_info_by_name: false,
                volume_params,
                guard_strategy: OperationGuardStrategy::Fine,
                debug_mode: DebugMode::none(),
            },
            context,
        )
    }

    /// Create a `FileSystemHost` with the provided context implementation, and
    /// host options.
    pub fn new_with_options<T: FileSystemContext + 'ctx>(
        options: FileSystemParams,
        context: T,
    ) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner(options, context)?;
        Ok(FileSystemHost(
            fsp_struct,
            #[cfg(feature = "notify")]
            None,
            PhantomData::default(),
        ))
    }

    /// Create a `FileSystemHost` with the provided notifying context implementation,
    /// host options, and polling interval.
    #[cfg(feature = "notify")]
    pub fn new_with_timer<
        T: FileSystemContext + NotifyingFileSystemContext<R> + 'ctx,
        R,
        const INTERVAL: u32,
    >(
        options: FileSystemParams,
        context: T,
    ) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner(options, context)?;
        let timer = Timer::create::<R, T, INTERVAL>(fsp_struct);
        Ok(FileSystemHost(
            fsp_struct,
            Some(timer),
            PhantomData::default(),
        ))
    }

    /// Start the filesystem dispatcher for this filesystem.
    pub fn start(&mut self) -> Result<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.0.as_ptr(), 0) };
        let result = NTSTATUS(result);
        result.ok()
    }

    /// Stop the filesystem dispatcher for this filesystem.
    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.0.as_ptr()) }
    }

    /// Mount the filesystem to the given mount point.
    pub fn mount<S: AsRef<OsStr>>(&mut self, mount: S) -> Result<()> {
        let mount = HSTRING::from(mount.as_ref());
        let result =
            unsafe { FspFileSystemSetMountPoint(self.0.as_ptr(), mount.as_ptr().cast_mut()) };

        let result = NTSTATUS(result);
        result.ok()
    }

    /// Unmount the filesystem. It is safe to call this function even if the
    /// file system is not mounted.
    pub fn unmount(&mut self) {
        unsafe { FspFileSystemRemoveMountPoint(self.0.as_ptr()) }
    }
}
