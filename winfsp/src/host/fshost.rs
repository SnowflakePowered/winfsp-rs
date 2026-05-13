use std::cell::UnsafeCell;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::ptr::null_mut;
use windows::Win32::Foundation::NTSTATUS;
use windows::core::HSTRING;
use windows::core::Result;

use winfsp_sys::{
    FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE,
    FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE,
    FspFileSystemCreate, FspFileSystemDelete, FspFileSystemRemoveMountPoint,
    FspFileSystemSetMountPoint, FspFileSystemSetOperationGuardStrategyF,
    FspFileSystemStartDispatcher, FspFileSystemStopDispatcher,
};

#[cfg(feature = "async-io")]
use crate::filesystem::AsyncFileSystemContext;
use crate::filesystem::FileSystemContext;
use crate::host::interface::{FileSystemUserContext, Interface};
use crate::host::{DebugMode, VolumeParams};

use crate::notify::NotifyingFileSystemContext;
use crate::notify::Timer;

/// Mount point for a new file system. Used by [`FileSystemHost::mount`].
pub enum MountPoint<'a> {
    /// A drive letter such as `X:` or directory path such as `path/to/folder`.
    MountPoint(&'a OsStr),
    /// Use the next available drive letter counting downwards from `Z:` as the mount point.
    NextFreeDrive,
}

/// Create a mount point from anything that can be viewed as a file path.
impl<'a, S> From<&'a S> for MountPoint<'a>
where
    S: AsRef<OsStr> + ?Sized,
{
    fn from(s: &'a S) -> Self {
        Self::MountPoint(s.as_ref())
    }
}
impl<'short, 'long, 'middle> From<&'short MountPoint<'long>> for MountPoint<'middle>
where
    'long: 'middle,
{
    fn from(s: &'short MountPoint<'long>) -> Self {
        match s {
            MountPoint::MountPoint(v) => MountPoint::MountPoint(v),
            MountPoint::NextFreeDrive => MountPoint::NextFreeDrive,
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed marker trait that selects the WinFSP operation-guard locking strategy
/// at the type level.
///
/// Only [`FineStrategy`] and [`CoarseStrategy`] implement this trait. It is used as a type
/// parameter on [`FileSystemHost`] to drive both the runtime call to
/// `FspFileSystemSetOperationGuardStrategy` and the bounds required to start the
/// dispatcher safely.
pub trait OperationGuardStrategy: sealed::Sealed {
    #[doc(hidden)]
    const RAW: i32;
}

/// Fine-grained concurrency strategy.
///
/// File system NAMESPACE accesses are guarded using an exclusive-shared
/// (read-write) lock. File I/O is not guarded and concurrent reads/writes/etc.
/// are possible. Note that the FSD will still apply an exclusive-shared lock
/// PER INDIVIDUAL FILE, but it will not limit I/O operations for different files.
///
/// The fine-grained concurrency model applies the exclusive-shared lock as follows:
/// * EXCL: `set_volume_label`, `flush(None)`, `create`, `cleanup` (delete), `rename`
/// * SHRD: `get_volume_info`, `open`, `set_delete`, `read_directory`
/// * NONE: all other operations
///
/// This is the default strategy. Because callbacks may run concurrently on
/// multiple dispatcher threads, [`FileSystemHost::start`] requires both `T` and
/// `T::FileContext` to be [`Sync`] under this strategy.
#[derive(Debug)]
pub enum FineStrategy {}
impl sealed::Sealed for FineStrategy {}
impl OperationGuardStrategy for FineStrategy {
    const RAW: i32 =
        FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
}

/// Coarse-grained concurrency strategy.
///
/// All file system accesses are guarded by a mutually exclusive lock held by
/// WinFSP. As a result, only one callback runs at a time even across multiple
/// dispatcher threads — equivalent to wrapping the entire filesystem in a
/// `Mutex<T>`. Under this strategy [`FileSystemHost::start`] only requires
/// `T` and `T::FileContext` to be [`Send`].
#[derive(Debug)]
pub enum CoarseStrategy {}
impl sealed::Sealed for CoarseStrategy {}
impl OperationGuardStrategy for CoarseStrategy {
    const RAW: i32 =
        FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE;
}

/// Options to create the filesystem with.
pub struct FileSystemParams {
    /// Enable the file system driver to call [`FileSystemContext::get_dir_info_by_name`](crate::filesystem::FileSystemContext::get_dir_info_by_name).
    pub use_dir_info_by_name: bool,
    /// The parameters to mount the volume with.
    pub volume_params: VolumeParams,
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
            debug_mode: Default::default(),
        }
    }

    /// Use the default options with the given volume parameters and debug mode.
    pub fn default_params_debug(volume_params: VolumeParams, debug_mode: DebugMode) -> Self {
        Self {
            use_dir_info_by_name: false,
            volume_params,
            debug_mode,
        }
    }
}
/// The user-mode filesystem host that manages the lifetime of the mounted filesystem.
///
/// This is separate from the lifetime of the service which is managed by
/// [`FileSystemService`](crate::service::FileSystemService). A `FileSystemHost`
/// should start within the context of a service.
///
/// The locking strategy used by WinFSP is selected via the `S` type parameter,
/// which defaults to [`Fine`]. See [`OperationGuardStrategy`] for the available
/// choices and their soundness implications.
pub struct FileSystemHost<T: FileSystemContext, S: OperationGuardStrategy = FineStrategy> {
    fsp_struct: NonNull<FSP_FILE_SYSTEM>,
    #[allow(dead_code)]
    timer: Option<Timer>,
    phantom: PhantomData<(T, S)>,
}

#[cfg(feature = "async-io")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "async-io")))]
impl<T: FileSystemContext + AsyncFileSystemContext, S: OperationGuardStrategy> FileSystemHost<T, S>
where
    <T as FileSystemContext>::FileContext: Sync,
{
    fn new_filesystem_inner_async(
        options: FileSystemParams,
        context: T,
    ) -> Result<NonNull<FSP_FILE_SYSTEM>> {
        #[allow(unused_variables)]
        let FileSystemParams {
            use_dir_info_by_name,
            volume_params,
            debug_mode,
        } = options;

        let interface = if use_dir_info_by_name {
            Interface::create_with_dirinfo_by_name_async::<T>()
        } else {
            Interface::create_with_read_directory_async::<T>()
        };

        Self::new_filesystem_inner_iface(interface, volume_params, debug_mode, context)
    }

    /// Create a `FileSystemHost` with the default settings
    /// for the provided context implementation, using async implementations of `read`, `write`, and `read_directory`.
    pub fn new_async(volume_params: VolumeParams, context: T) -> Result<Self> {
        Self::new_with_options_async(
            FileSystemParams {
                use_dir_info_by_name: false,
                volume_params,
                debug_mode: DebugMode::none(),
            },
            context,
        )
    }

    /// Create a `FileSystemHost` with the provided context implementation, and
    /// host options, using async implementations of `read`, `write`, and `read_directory`.
    pub fn new_with_options_async(options: FileSystemParams, context: T) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner_async(options, context)?;
        Ok(FileSystemHost {
            fsp_struct,
            timer: None,
            phantom: PhantomData,
        })
    }

    /// Create a `FileSystemHost` with the provided notifying context implementation,
    /// host options, and polling interval, using async implementations of `read`, `write`, and `read_directory`.
    #[cfg_attr(
        feature = "docsrs",
        doc(cfg(all(feature = "notify", feature = "async-io")))
    )]
    #[cfg(all(feature = "notify", feature = "async-io"))]
    pub fn new_with_timer_async<R, const INTERVAL: u32>(
        options: FileSystemParams,
        context: T,
    ) -> Result<Self>
    where
        T: NotifyingFileSystemContext<R>,
    {
        let fsp_struct = Self::new_filesystem_inner_async(options, context)?;
        let timer = Timer::create::<R, T, INTERVAL>(fsp_struct)?;

        Ok(FileSystemHost {
            fsp_struct,
            timer: Some(timer),
            phantom: PhantomData,
        })
    }
}

impl<T: FileSystemContext, S: OperationGuardStrategy> FileSystemHost<T, S> {
    #[allow(unused_variables)]
    fn new_filesystem_inner_iface(
        interface: Interface,
        volume_params: VolumeParams,
        debug_mode: DebugMode,
        context: T,
    ) -> Result<NonNull<FSP_FILE_SYSTEM>> {
        let mut fsp_struct = std::ptr::null_mut();

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
            (*fsp_struct).UserContext = Box::into_raw(Box::new(UnsafeCell::new(
                FileSystemUserContext::new(context),
            ))) as *mut _;

            FspFileSystemSetOperationGuardStrategyF(fsp_struct, S::RAW);
        }

        assert!(!fsp_struct.is_null());
        Ok(NonNull::new(fsp_struct).expect("FSP_FILE_SYSTEM pointer was created but was null!"))
    }

    fn new_filesystem_inner(
        options: FileSystemParams,
        context: T,
    ) -> Result<NonNull<FSP_FILE_SYSTEM>> {
        #[allow(unused_variables)]
        let FileSystemParams {
            use_dir_info_by_name,
            volume_params,
            debug_mode,
        } = options;

        let interface = if use_dir_info_by_name {
            Interface::create_with_dirinfo_by_name::<T>()
        } else {
            Interface::create_with_read_directory::<T>()
        };

        Self::new_filesystem_inner_iface(interface, volume_params, debug_mode, context)
    }

    /// Create a `FileSystemHost` with the default settings
    /// for the provided context implementation.
    pub fn new(volume_params: VolumeParams, context: T) -> Result<Self> {
        Self::new_with_options(
            FileSystemParams {
                use_dir_info_by_name: false,
                volume_params,
                debug_mode: DebugMode::none(),
            },
            context,
        )
    }

    /// Create a `FileSystemHost` with the provided context implementation, and
    /// host options.
    pub fn new_with_options(options: FileSystemParams, context: T) -> Result<Self> {
        let fsp_struct = Self::new_filesystem_inner(options, context)?;
        Ok(FileSystemHost {
            fsp_struct,
            timer: None,
            phantom: PhantomData,
        })
    }

    /// Create a `FileSystemHost` with the provided notifying context implementation,
    /// host options, and polling interval.
    #[cfg_attr(feature = "docsrs", doc(cfg(feature = "notify")))]
    #[cfg(feature = "notify")]
    pub fn new_with_timer<R, const INTERVAL: u32>(
        options: FileSystemParams,
        context: T,
    ) -> Result<Self>
    where
        T: NotifyingFileSystemContext<R>,
    {
        let fsp_struct = Self::new_filesystem_inner(options, context)?;
        let timer = Timer::create::<R, T, INTERVAL>(fsp_struct)?;
        Ok(FileSystemHost {
            fsp_struct,
            timer: Some(timer),
            phantom: PhantomData,
        })
    }

    /// Stop the filesystem dispatcher for this filesystem.
    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.fsp_struct.as_ptr()) }
    }

    /// Mount the filesystem to the given mount point.
    ///
    /// # Examples
    ///
    /// ```
    /// use winfsp::host::{FileSystemHost, MountPoint};
    /// use winfsp::filesystem::FileSystemContext;
    ///
    /// fn mount_file_system<T: FileSystemContext>(host: &mut FileSystemHost<T>) -> winfsp::Result<()> {
    ///     // Can mount in one of the following ways:
    ///     host.mount("X:")?;
    ///     host.mount("../MyFileSystem".to_string())?;
    ///     host.mount(&std::path::PathBuf::from("C:/WinFspFileSystem"))?;
    ///     host.mount(MountPoint::NextFreeDrive)?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn mount<M>(&mut self, mount: M) -> Result<()>
    where
        // Convert a reference to the provided value in order to allow the
        // caller to provide owned values such as `String`:
        for<'b> &'b M: Into<MountPoint<'b>>,
    {
        let mount_str: HSTRING;
        let mount_ptr = match <&M as Into<MountPoint<'_>>>::into(&mount) {
            MountPoint::MountPoint(mount) => {
                mount_str = HSTRING::from(mount);
                // Pointer is valid until `mount_str` is dropped at the end of the function.
                mount_str.as_ptr().cast_mut()
            }
            MountPoint::NextFreeDrive => null_mut(),
        };
        let result = unsafe { FspFileSystemSetMountPoint(self.fsp_struct.as_ptr(), mount_ptr) };

        let result = NTSTATUS(result);
        result.ok()
    }

    /// Unmount the filesystem. It is safe to call this function even if the
    /// file system is not mounted.
    pub fn unmount(&mut self) {
        unsafe { FspFileSystemRemoveMountPoint(self.fsp_struct.as_ptr()) }
    }
}

impl<T: FileSystemContext + Sync> FileSystemHost<T, FineStrategy>
where
    <T as FileSystemContext>::FileContext: Sync,
{
    /// Start the filesystem dispatcher for this filesystem.
    ///
    /// Under the [`Fine`] guard strategy WinFSP invokes filesystem callbacks
    /// from multiple kernel-managed dispatcher threads concurrently through
    /// shared references, so both `T` and `T::FileContext` must be [`Sync`].
    pub fn start(&mut self) -> Result<()> {
        self.start_with_threads(0)
    }

    /// Start the filesystem dispatcher for this filesystem with the specified number of threads.
    ///
    /// Under the [`Fine`] guard strategy WinFSP invokes filesystem callbacks
    /// from multiple kernel-managed dispatcher threads concurrently through
    /// shared references, so both `T` and `T::FileContext` must be [`Sync`].
    pub fn start_with_threads(&mut self, num_threads: u32) -> Result<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.fsp_struct.as_ptr(), num_threads) };
        let result = NTSTATUS(result);
        result.ok()
    }
}

impl<T: FileSystemContext + Send> FileSystemHost<T, CoarseStrategy>
where
    <T as FileSystemContext>::FileContext: Send,
{
    /// Start the filesystem dispatcher for this filesystem.
    ///
    /// Under the [`Coarse`] guard strategy WinFSP serialises all callbacks
    /// behind an exclusive lock, so `T` and `T::FileContext` only need to be
    /// [`Send`] — never two threads inside a callback at once, equivalent to
    /// wrapping the whole filesystem in a `Mutex`.
    pub fn start(&mut self) -> Result<()> {
        self.start_with_threads(0)
    }

    /// Start the filesystem dispatcher for this filesystem with the specified number of threads.
    ///
    /// Under the [`Coarse`] guard strategy WinFSP serialises all callbacks
    /// behind an exclusive lock, so `T` and `T::FileContext` only need to be
    /// [`Send`] — never two threads inside a callback at once, equivalent to
    /// wrapping the whole filesystem in a `Mutex`.
    pub fn start_with_threads(&mut self, num_threads: u32) -> Result<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.fsp_struct.as_ptr(), num_threads) };
        let result = NTSTATUS(result);
        result.ok()
    }
}

/// Testing that the lifetime of the user context must outlive the lifetime of the WinfspHost
///
/// Note that this test only checks that this does not compile, and can't the reason
/// a more proper test would verify that this code would compile if lifetimes are valid
/// ```rust, compile_fail
/// use winfsp::host::{FileSystemHost, VolumeParams};
/// use winfsp::filesystem::{FileSystemContext, FileSecurity, OpenFileInfo};
/// use winfsp::{Result, U16CStr};
/// use std::ffi::c_void;
///
///
/// struct NullContext<'a> {
///     data: &'a u8,
/// }
///
/// impl<'a> FileSystemContext for NullContext<'a> {
///     type FileContext = ();
///
///     fn get_security_by_name(&self, _: &U16CStr, _: Option<&mut [c_void]>,
///         _: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
///     ) -> Result<FileSecurity> {
///         todo!()
///     }
///
///     fn open(
///         &self,
///         _: &U16CStr,
///         _: u32,
///         _: winfsp_sys::FILE_ACCESS_RIGHTS,
///         _: &mut OpenFileInfo,
///     ) -> Result<()> {
///         todo!()
///     }
///
///     fn close(&self, _: ()) {
///         todo!()
///     }
/// }
///
/// let host;
/// {
///     let data = 0;
///     let context = NullContext{data: &data};
///     host = FileSystemHost::new(VolumeParams::default(), context).expect("")
/// }
/// drop(host);
///
/// ```
impl<T: FileSystemContext, S: OperationGuardStrategy> Drop for FileSystemHost<T, S> {
    fn drop(&mut self) {
        // Tear the notify timer down FIRST, before anything else. Its Drop
        // disarms the threadpool timer and blocks until in-flight callbacks
        // return. Struct fields drop *after* this user-impl finishes, which
        // would be too late: the timer callback dereferences `UserContext`
        // and `FSP_FILE_SYSTEM`, both of which we're about to free below.
        drop(self.timer.take());

        // Wait for any spawned async filesystem callbacks to release their
        // borrow of UserContext and any WinFSP request buffers. The barrier
        // lives inside the UserContext box (still allocated at this point);
        // each spawned task holds an `InFlightGuard` that decrements the
        // barrier on drop, whether by natural completion, executor
        // cancellation, or panic.
        //
        // `begin_drain_and_wait` atomically (a) refuses any further `enter`
        // attempts and (b) parks until the live-task count reaches zero.
        // The atomicity matters: without the draining flag the WinFSP
        // dispatcher could spawn one last task between the `count == 0`
        // observation and `stop()` below, leaving its `&UserContext` to
        // dangle past the `Box::from_raw` further down.
        //
        // By the time this returns, no task is in scope and no new task
        // can be spawned by the framework, so it's safe to call `stop`
        // (which triggers FspIoqStop and tears down IRP buffer mappings)
        // and then free the UserContext box.
        #[cfg(feature = "async-io")]
        unsafe {
            let uc = &*self
                .fsp_struct
                .as_ref()
                .UserContext
                .cast::<FileSystemUserContext<T>>();
            uc.in_flight.begin_drain_and_wait();
        }

        self.unmount();
        self.stop();
        unsafe {
            // SAFETY: FSP is stopped and no longer running anything on this
            // filesystem, the notify timer (if any) has been fully joined,
            // and any spawned async tasks have released their barrier guard,
            // so nothing else can reach UserContext or fsp_struct.
            let user_context =
                self.fsp_struct.as_ref().UserContext as *mut UnsafeCell<FileSystemUserContext<T>>;
            let interface = self.fsp_struct.as_ref().Interface as *mut UnsafeCell<Interface>;

            FspFileSystemDelete(self.fsp_struct.as_ptr());

            let user_context = Box::from_raw(user_context);
            drop(user_context);
            let interface = Box::<UnsafeCell<Interface>>::from_raw(interface);
            drop(interface);
        };
    }
}

/// SAFETY: FileSystemHost does not expose fsp_struct and cannot be cloned. The
/// `S` marker is uninhabited so it imposes no auto-trait constraints.
unsafe impl<T: FileSystemContext + Send, S: OperationGuardStrategy> Send for FileSystemHost<T, S> {}
