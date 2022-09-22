use windows::core::Result;
use windows::core::HSTRING;
use windows::w;
use windows::Win32::Foundation::NTSTATUS;

use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemRemoveMountPoint, FspFileSystemSetMountPoint,
    FspFileSystemStartDispatcher, FspFileSystemStopDispatcher, FSP_FILE_SYSTEM,
    FSP_FILE_SYSTEM_INTERFACE,
};

pub use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS};

use crate::filesystem::interface::Interface;
use crate::filesystem::notify::NotifyingFileSystemContext;
use crate::filesystem::sealed::Sealed;
use crate::filesystem::timer::Timer;
use crate::filesystem::FileSystemContext;

/// The strategy to use when resolving directories with the filesystem context.
pub trait DirectoryResolveStrategy: Sealed {
    #[doc(hidden)]
    fn create_interface<T: FileSystemContext<DIR_BUFFER_SIZE>, const DIR_BUFFER_SIZE: usize>(
    ) -> Interface;
}

/// Resolve directories with the [`read_directory`](crate::filesystem::FileSystemContext::read_directory)
/// function.
pub struct ReadDirectory;
impl DirectoryResolveStrategy for ReadDirectory {
    fn create_interface<T: FileSystemContext<DIR_BUFFER_SIZE>, const DIR_BUFFER_SIZE: usize>(
    ) -> Interface {
        Interface::create_with_read_directory::<T, DIR_BUFFER_SIZE>()
    }
}
/// Resolve directories with the [`get_dir_info_by_name`](crate::filesystem::FileSystemContext::get_dir_info_by_name)
/// function.
pub struct GetDirInfoByName;
impl DirectoryResolveStrategy for GetDirInfoByName {
    fn create_interface<T: FileSystemContext<DIR_BUFFER_SIZE>, const DIR_BUFFER_SIZE: usize>(
    ) -> Interface {
        Interface::create_with_dirinfo_by_name::<T, DIR_BUFFER_SIZE>()
    }
}

/// The user-mode filesystem host that manages the lifetime of the mounted filesystem.
///
/// This is separate from the lifetime of the service which is managed by
/// [`FileSystemService`](crate::service::FileSystemService). A `FileSystemHost`
/// should start within the context of a service.
pub struct FileSystemHost(pub *mut FSP_FILE_SYSTEM, Option<Timer>);
impl FileSystemHost {
    /// Create a `FileSystemHost` with the default `ReadDirectory` directory strategy
    /// for the provided context implementation.
    /// ## Safety
    /// `volume_params` must be valid.
    pub unsafe fn new<T: FileSystemContext<DIR_BUFFER_SIZE>, const DIR_BUFFER_SIZE: usize>(
        volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> Result<Self> {
        unsafe {
            Self::new_with_directory_strategy::<T, ReadDirectory, DIR_BUFFER_SIZE>(
                volume_params,
                context,
            )
        }
    }

    /// Create a `FileSystemHost` with the provided context implementation and directory
    /// resolution strategy.
    /// ## Safety
    /// `volume_params` must be valid.
    pub unsafe fn new_with_directory_strategy<
        T: FileSystemContext<DIR_BUFFER_SIZE>,
        D: DirectoryResolveStrategy,
        const DIR_BUFFER_SIZE: usize,
    >(
        volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> Result<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let interface = D::create_interface::<T, DIR_BUFFER_SIZE>();
        let interface: FSP_FILE_SYSTEM_INTERFACE = interface.into();
        let interface = Box::into_raw(Box::new(interface));
        let result = unsafe {
            FspFileSystemCreate(
                if volume_params.Prefix[0] != 0 {
                    w!("WinFsp.Net").as_ptr().cast_mut()
                } else {
                    w!("WinFsp.Disk").as_ptr().cast_mut()
                },
                &volume_params,
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
        Ok(FileSystemHost(fsp_struct, None))
    }

    /// Create a `FileSystemHost` with the provided context implementation,
    /// resolution strategy, and filesystem notification support.
    /// ## Safety
    /// `volume_params` must be valid.
    #[cfg(feature = "notify")]
    pub unsafe fn new_with_directory_strategy_and_timer<
        T: FileSystemContext<DIR_BUFFER_SIZE> + NotifyingFileSystemContext<R, DIR_BUFFER_SIZE>,
        D: DirectoryResolveStrategy,
        R,
        const DIR_BUFFER_SIZE: usize,
        const INTERVAL: u32,
    >(
        volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> Result<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let interface = D::create_interface::<T, DIR_BUFFER_SIZE>();
        let interface: FSP_FILE_SYSTEM_INTERFACE = interface.into();
        let interface = Box::into_raw(Box::new(interface));
        let result = unsafe {
            FspFileSystemCreate(
                if volume_params.Prefix[0] != 0 {
                    w!("WinFsp.Net").as_ptr().cast_mut()
                } else {
                    w!("WinFsp.Disk").as_ptr().cast_mut()
                },
                &volume_params,
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

        let timer = Timer::create::<R, T, INTERVAL, DIR_BUFFER_SIZE>(fsp_struct);
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
