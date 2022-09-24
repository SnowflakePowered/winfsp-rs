use windows::core::Result;
use windows::core::HSTRING;
use windows::Win32::Foundation::NTSTATUS;

use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemRemoveMountPoint, FspFileSystemSetMountPoint,
    FspFileSystemStartDispatcher, FspFileSystemStopDispatcher, FSP_FILE_SYSTEM,
    FSP_FILE_SYSTEM_INTERFACE,
};

use crate::filesystem::interface::Interface;
use crate::filesystem::{FileSystemContext, VolumeParams};

use crate::notify::NotifyingFileSystemContext;
use crate::notify::Timer;

/// The user-mode filesystem host that manages the lifetime of the mounted filesystem.
///
/// This is separate from the lifetime of the service which is managed by
/// [`FileSystemService`](crate::service::FileSystemService). A `FileSystemHost`
/// should start within the context of a service.
pub struct FileSystemHost(*mut FSP_FILE_SYSTEM, Option<Timer>);
impl FileSystemHost {
    fn new_filesystem_inner<T: FileSystemContext>(
        volume_params: VolumeParams,
        context: T,
        use_directory_by_name: bool,
    ) -> Result<*mut FSP_FILE_SYSTEM> {
        let mut fsp_struct = std::ptr::null_mut();

        let interface = if use_directory_by_name {
            Interface::create_with_dirinfo_by_name::<T>()
        } else {
            Interface::create_with_read_directory::<T>()
        };

        let interface: FSP_FILE_SYSTEM_INTERFACE = interface.into();
        let interface = Box::into_raw(Box::new(interface));
        let result = unsafe {
            FspFileSystemCreate(
                volume_params.get_winfsp_device_name(),
                &volume_params.0,
                interface,
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
            winfsp_sys::FspFileSystemSetDebugLogF(fsp_struct, u32::MAX);
        }

        unsafe {
            (*fsp_struct).UserContext = Box::into_raw(Box::new(context)) as *mut _;
        }
        Ok(fsp_struct)
    }

    /// Create a `FileSystemHost` with the default `ReadDirectory` directory strategy
    /// for the provided context implementation.
    pub fn new<T: FileSystemContext>(volume_params: VolumeParams, context: T) -> Result<Self> {
        Self::new_with_directory_by_name::<T>(volume_params, context, false)
    }

    /// Create a `FileSystemHost` with the provided context implementation and directory
    /// resolution strategy.
    pub fn new_with_directory_by_name<T: FileSystemContext>(
        volume_params: VolumeParams,
        context: T,
        use_directory_by_name: bool,
    ) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner(volume_params, context, use_directory_by_name)?;
        Ok(FileSystemHost(fsp_struct, None))
    }

    /// Create a `FileSystemHost` with the provided context implementation,
    /// resolution strategy, and filesystem notification support.
    #[cfg(feature = "notify")]
    pub fn new_with_directory_strategy_and_timer<
        T: FileSystemContext + NotifyingFileSystemContext<R>,
        R,
        const INTERVAL: u32,
    >(
        volume_params: VolumeParams,
        context: T,
        use_directory_by_name: bool,
    ) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner(volume_params, context, use_directory_by_name)?;
        let timer = Timer::create::<R, T, INTERVAL>(fsp_struct);
        Ok(FileSystemHost(fsp_struct, Some(timer)))
    }

    /// Start the filesystem dispatcher for this filesystem.
    pub fn start(&mut self) -> Result<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.0, 0) };
        let result = NTSTATUS(result);
        result.ok()
    }

    /// Stop the filesystem dispatcher for this filesystem.
    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.0) }
    }

    /// Mount the filesystem to the given mount point.
    pub fn mount<S: Into<HSTRING>>(&mut self, mount: S) -> Result<()> {
        let result =
            unsafe { FspFileSystemSetMountPoint(self.0, mount.into().as_ptr().cast_mut()) };

        let result = NTSTATUS(result);
        result.ok()
    }

    /// Unmount the filesystem. It is safe to call this function even if the
    /// file system is not mounted.
    pub fn unmount(&mut self) {
        unsafe { FspFileSystemRemoveMountPoint(self.0) }
    }
}
