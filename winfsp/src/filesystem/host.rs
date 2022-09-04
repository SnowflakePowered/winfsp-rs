use windows::core::Result;
use windows::core::HSTRING;
use windows::w;
use windows::Win32::Foundation::NTSTATUS;

use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemSetMountPoint, FspFileSystemStartDispatcher,
    FspFileSystemStopDispatcher, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE,
};

pub use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS};

use crate::filesystem::interface::Interface;
use crate::filesystem::FileSystemContext;

/// The user-mode filesystem host that manages the lifetime of the mounted filesystem.
///
/// This is separate from the lifetime of the service which is managed by
/// [`FileSystemService`](crate::service::FileSystemService). A `FileSystemHost`
/// should start within the context of a service.
pub struct FileSystemHost(pub *mut FSP_FILE_SYSTEM);
impl FileSystemHost {
    /// # Safety
    /// `volume_params` must be valid.
    pub unsafe fn new<T: FileSystemContext>(
        volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> Result<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let interface = Interface::create::<T>();
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
        Ok(FileSystemHost(fsp_struct))
    }

    pub fn start(&mut self) -> Result<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.0, 0) };
        let result = NTSTATUS(result);
        result.ok()
    }

    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.0) }
    }

    pub fn mount<S: Into<HSTRING>>(&mut self, mount: S) -> Result<()> {
        let result =
            unsafe { FspFileSystemSetMountPoint(self.0, mount.into().as_ptr().cast_mut()) };

        let result = NTSTATUS(result);
        result.ok()
    }
}
