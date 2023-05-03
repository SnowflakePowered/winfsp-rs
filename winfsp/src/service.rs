//! Interfaces to the WinFSP service API to run a filesystem.
use crate::error::FspError;
use crate::FspInit;
use crate::Result;
use std::cell::UnsafeCell;
use std::ffi::{c_void, OsStr};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::thread::JoinHandle;
use windows::core::HSTRING;
use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use winfsp_sys::{
    FspServiceAllowConsoleMode, FspServiceCreate, FspServiceLoop, FspServiceStop, FSP_SERVICE,
};

// internal aliases for callback types
type FileSystemStartCallback<T> = Option<Box<dyn Fn() -> std::result::Result<T, NTSTATUS>>>;
type FileSystemStopCallback<T> =
    Option<Box<dyn Fn(Option<&mut T>) -> std::result::Result<(), NTSTATUS>>>;
type FileSystemControlCallback<T> =
    Option<Box<dyn Fn(Option<&mut T>, u32, u32, *mut c_void) -> i32>>;
struct FileSystemServiceContext<T> {
    start: FileSystemStartCallback<T>,
    stop: FileSystemStopCallback<T>,
    control: FileSystemControlCallback<T>,
    context: Option<Box<T>>,
}

struct AssertThreadSafe<T>(*mut T);
unsafe impl<T> Send for AssertThreadSafe<T> {}
unsafe impl<T> Sync for AssertThreadSafe<T> {}

/// A service that runs a filesystem implemented by a [`FileSystemHost`](crate::filesystem::FileSystemHost).
pub struct FileSystemService<T>(NonNull<FSP_SERVICE>, PhantomData<T>);
impl<T> FileSystemService<T> {
    /// # Safety
    /// `raw` is valid and not null.
    unsafe fn from_raw_unchecked(raw: *mut FSP_SERVICE) -> Self {
        unsafe { FileSystemService(NonNull::new_unchecked(raw), Default::default()) }
    }

    /// Set the context.
    fn set_context(&mut self, context: T) {
        unsafe {
            let ptr: *mut UnsafeCell<FileSystemServiceContext<T>> =
                self.0.as_mut().UserContext.cast();
            if let Some(ptr) = ptr.as_mut() {
                ptr.get_mut().context = Some(Box::new(context))
            }
        }
    }

    fn get_context(&mut self) -> Option<&mut T> {
        unsafe {
            if let Some(p) = self
                .0
                .as_mut()
                .UserContext
                .cast::<UnsafeCell<FileSystemServiceContext<T>>>()
                .as_mut()
            {
                p.get_mut().context.as_deref_mut()
            } else {
                None
            }
        }
    }
}

impl<T> FileSystemService<T> {
    /// Stops the file system host service.
    pub fn stop(&self) {
        unsafe {
            FspServiceStop(self.0.as_ptr());
        };
    }

    /// Spawns a thread and starts the file host system service.
    pub fn start(&self) -> JoinHandle<Result<()>> {
        let ptr = AssertThreadSafe(self.0.as_ptr());
        std::thread::spawn(|| {
            let ptr = ptr;
            let result = unsafe {
                FspServiceAllowConsoleMode(ptr.0);
                FspServiceLoop(ptr.0)
            };

            if result == STATUS_SUCCESS.0 {
                Ok(())
            } else {
                Err(FspError::NTSTATUS(NTSTATUS(result)))
            }
        })
    }
}

/// A builder for [`FileSystemService`](crate::service::FileSystemService).
pub struct FileSystemServiceBuilder<T> {
    stop: FileSystemStopCallback<T>,
    start: FileSystemStartCallback<T>,
    control: FileSystemControlCallback<T>,
}

impl<T> Default for FileSystemServiceBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FileSystemServiceBuilder<T> {
    /// Create a new instance of the builder.
    pub fn new() -> Self {
        Self {
            stop: None,
            start: None,
            control: None,
        }
    }

    /// The start callback provides the file system context and mounts the file system.
    /// The returned file system context must be mounted before returning.
    pub fn with_start<F>(mut self, start: F) -> Self
    where
        F: Fn() -> std::result::Result<T, NTSTATUS> + 'static,
    {
        self.start = Some(Box::new(start));
        self
    }

    /// The stop callback is responsible for safely terminating the mounted file system.
    pub fn with_stop<F>(mut self, stop: F) -> Self
    where
        F: Fn(Option<&mut T>) -> std::result::Result<(), NTSTATUS> + 'static,
    {
        self.stop = Some(Box::new(stop));
        self
    }

    /// The control callback handles DeviceIoControl requests.
    pub fn with_control<F>(mut self, control: F) -> Self
    where
        F: Fn(Option<&mut T>, u32, u32, *mut c_void) -> i32 + 'static,
    {
        self.control = Some(Box::new(control));
        self
    }

    /// Create the [`FileSystemService`](crate::service::FileSystemService) with the provided
    /// callbacks.
    pub fn build(self, service_name: impl AsRef<OsStr>, _init: FspInit) -> Result<FileSystemService<T>> {
        let mut service = std::ptr::null_mut();
        let service_name = HSTRING::from(service_name.as_ref());
        let result = unsafe {
            // SAFETY: service_name is never mutated.
            // https://github.com/winfsp/winfsp/blob/0ab4300738233eba4a37e1302e55fff6f0c4f5ab/src/dll/service.c#L108
            FspServiceCreate(
                service_name.as_ptr().cast_mut(),
                Some(on_start::<T>),
                Some(on_stop::<T>),
                Some(on_control::<T>),
                &mut service,
            )
        };

        unsafe { service.as_mut() }.unwrap().UserContext =
            Box::into_raw(Box::new(UnsafeCell::new(FileSystemServiceContext::<T> {
                start: self.start,
                stop: self.stop,
                control: self.control,
                context: None,
            }))) as *mut _;
        if result == STATUS_SUCCESS.0 && !service.is_null() {
            Ok(unsafe { FileSystemService::from_raw_unchecked(service) })
        } else {
            Err(FspError::NTSTATUS(NTSTATUS(result)))
        }
    }
}

unsafe extern "C" fn on_start<T>(fsp: *mut FSP_SERVICE, _argc: u32, _argv: *mut *mut u16) -> i32 {
    if let Some(context) = unsafe {
        fsp.as_mut()
            .unwrap_unchecked()
            .UserContext
            .cast::<FileSystemServiceContext<T>>()
            .as_mut()
    } {
        if let Some(start) = &context.start {
            return match start() {
                Err(e) => e.0,
                Ok(context) => {
                    unsafe {
                        FileSystemService::from_raw_unchecked(fsp).set_context(context);
                    }
                    STATUS_SUCCESS.0
                }
            };
        }
    }
    STATUS_INVALID_PARAMETER.0
}

unsafe extern "C" fn on_stop<T>(fsp: *mut FSP_SERVICE) -> i32 {
    if let Some(context) = unsafe {
        fsp.as_mut()
            .unwrap_unchecked()
            .UserContext
            .cast::<FileSystemServiceContext<T>>()
            .as_mut()
    } {
        if let Some(stop) = &context.stop {
            let mut fsp = unsafe { FileSystemService::from_raw_unchecked(fsp) };
            let context = fsp.get_context();

            return match stop(context) {
                Ok(()) => STATUS_SUCCESS.0,
                Err(e) => e.0,
            };
        }
    }
    STATUS_INVALID_PARAMETER.0
}

unsafe extern "C" fn on_control<T>(
    fsp: *mut FSP_SERVICE,
    ctl: u32,
    event_type: u32,
    event_data: *mut c_void,
) -> i32 {
    if let Some(context) = unsafe {
        fsp.as_mut()
            .unwrap_unchecked()
            .UserContext
            .cast::<FileSystemServiceContext<T>>()
            .as_mut()
    } {
        if let Some(control) = &context.control {
            let mut fsp = unsafe { FileSystemService::from_raw_unchecked(fsp) };
            let context = fsp.get_context();

            return control(context, ctl, event_type, event_data);
        }
    }
    STATUS_INVALID_PARAMETER.0
}
