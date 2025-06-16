//! Interfaces to the WinFSP service API to run a filesystem.
use crate::error::FspError;
use crate::util::AssertThreadSafe;
use crate::FspInit;
use crate::Result;
use std::cell::UnsafeCell;
use std::ffi::{c_void, OsStr};
use std::marker::PhantomData;
use std::ptr::{addr_of_mut, NonNull};
use std::thread::JoinHandle;
use windows::core::HSTRING;
use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use winfsp_sys::{
    FspServiceAllowConsoleMode, FspServiceCreate, FspServiceDelete, FspServiceLoop, FspServiceStop,
    FSP_SERVICE,
};

// internal aliases for callback types
type FileSystemStartCallback<'a, T> =
    Option<Box<dyn Fn() -> std::result::Result<T, NTSTATUS> + 'a>>;
type FileSystemStopCallback<'a, T> =
    Option<Box<dyn Fn(Option<&mut T>) -> std::result::Result<(), NTSTATUS> + 'a>>;
type FileSystemControlCallback<'a, T> =
    Option<Box<dyn Fn(Option<&mut T>, u32, u32, *mut c_void) -> i32 + 'a>>;
struct FileSystemServiceContext<'a, T> {
    start: FileSystemStartCallback<'a, T>,
    stop: FileSystemStopCallback<'a, T>,
    control: FileSystemControlCallback<'a, T>,
    context: Option<Box<T>>,
}

/// A service that runs a filesystem implemented by a [`FileSystemHost`](crate::host::FileSystemHost).
pub struct FileSystemService<T>(NonNull<FSP_SERVICE>, PhantomData<T>);

struct FileSystemServiceHelper<T>(NonNull<FSP_SERVICE>, PhantomData<T>);

impl<T> FileSystemServiceHelper<T> {
    /// # Safety
    /// `raw` is valid and not null.
    unsafe fn from_raw_unchecked(raw: *mut FSP_SERVICE) -> Self {
        unsafe { FileSystemServiceHelper(NonNull::new_unchecked(raw), Default::default()) }
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
            #[allow(clippy::redundant_locals)]
            let ptr = ptr;
            let result = unsafe {
                FspServiceAllowConsoleMode(ptr.0);
                FspServiceLoop(ptr.0)
            };

            if result == STATUS_SUCCESS.0 {
                Ok(())
            } else {
                Err(FspError::NTSTATUS(result))
            }
        })
    }
}

/// A builder for [`FileSystemService`](crate::service::FileSystemService).
pub struct FileSystemServiceBuilder<'a, T> {
    stop: FileSystemStopCallback<'a, T>,
    start: FileSystemStartCallback<'a, T>,
    control: FileSystemControlCallback<'a, T>,
}

impl<'a, T> Default for FileSystemServiceBuilder<'a, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T> FileSystemServiceBuilder<'a, T> {
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
        F: Fn() -> std::result::Result<T, NTSTATUS> + 'a,
    {
        self.start = Some(Box::new(start));
        self
    }

    /// The stop callback is responsible for safely terminating the mounted file system.
    pub fn with_stop<F>(mut self, stop: F) -> Self
    where
        F: Fn(Option<&mut T>) -> std::result::Result<(), NTSTATUS> + 'a,
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
    pub fn build(
        self,
        service_name: impl AsRef<OsStr>,
        _init: FspInit,
    ) -> Result<FileSystemService<T>> {
        let service = UnsafeCell::new(std::ptr::null_mut());
        let service_name = HSTRING::from(service_name.as_ref());
        let result = unsafe {
            // SAFETY: service_name is never mutated.
            // https://github.com/winfsp/winfsp/blob/0ab4300738233eba4a37e1302e55fff6f0c4f5ab/src/dll/service.c#L108
            FspServiceCreate(
                service_name.as_ptr().cast_mut(),
                Some(on_start::<T>),
                Some(on_stop::<T>),
                Some(on_control::<T>),
                service.get(),
            )
        };

        unsafe {
            addr_of_mut!((*(*service.get())).UserContext).write(Box::into_raw(Box::new(
                UnsafeCell::new(FileSystemServiceContext::<T> {
                    start: self.start,
                    stop: self.stop,
                    control: self.control,
                    context: None,
                }),
            )) as *mut _)
        }
        if result == STATUS_SUCCESS.0 && unsafe { !service.get().read().is_null() } {
            Ok(unsafe {
                FileSystemService(NonNull::new_unchecked(service.get().read()), PhantomData)
            })
        } else {
            Err(FspError::NTSTATUS(result))
        }
    }
}

impl<'a, T> Drop for FileSystemService<T> {
    fn drop(&mut self) {
        self.stop();
        let service_context_ptr = unsafe {
            // SAFETY: FSP_SERVICE pointer and UserContext field are not mutated by other threads
            self.0.as_ref().UserContext as *mut UnsafeCell<FileSystemServiceContext<T>>
        };
        unsafe {
            FspServiceDelete(self.0.as_ptr());
        };
        let service_context_box = unsafe {
            // SAFETY: No other threads exist with access to the service context and its type is correct
            Box::<UnsafeCell<FileSystemServiceContext<T>>>::from_raw(service_context_ptr)
        };
        drop(service_context_box);
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
                        FileSystemServiceHelper::from_raw_unchecked(fsp).set_context(context);
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
            let mut fsp = unsafe { FileSystemServiceHelper::from_raw_unchecked(fsp) };
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
            let mut fsp = unsafe { FileSystemServiceHelper::from_raw_unchecked(fsp) };
            let context = fsp.get_context();

            return control(context, ctl, event_type, event_data);
        }
    }
    STATUS_INVALID_PARAMETER.0
}
