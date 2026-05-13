//! Interfaces to the WinFSP service API to run a filesystem.
use crate::FspInit;
use crate::Result;
use crate::error::FspError;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::ffi::{OsStr, c_void};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::thread::JoinHandle;
use windows::Win32::Foundation::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use windows::core::HSTRING;
use winfsp_sys::{
    FSP_SERVICE, FspServiceAllowConsoleMode, FspServiceCreate, FspServiceDelete, FspServiceLoop,
    FspServiceStop,
};

/// Send-able wrapper around the WinFSP service pointer so the worker thread
/// in [`FileSystemService::start`] can hold onto it.
struct ServicePtr(*mut FSP_SERVICE);

// SAFETY: The pointer references an FSP_SERVICE that is owned by the
// FileSystemService instance which spawned the worker. FileSystemService::Drop
// signals stop and joins the worker before calling FspServiceDelete, so the
// pointer stays valid for the worker's entire lifetime. FspServiceLoop and
// FspServiceAllowConsoleMode are documented to be safe to call from a thread
// other than the one that created the service.
unsafe impl Send for ServicePtr {}

// internal aliases for callback types
//
// `Send + Sync` is required because the WinFSP SCM control dispatcher invokes
// `on_stop` / `on_control` on a *different* thread from the service main
// thread that runs `on_start` (see `FspServiceCtrlHandler` /
// `FspServiceMain` in winfsp's `src/dll/service.c`). The boxed trait
// objects are reached through `&FileSystemServiceContext` from both threads,
// so the underlying closures must themselves be `Sync`.
type FileSystemStartCallback<'a, T> =
    Option<Box<dyn Fn() -> std::result::Result<T, FspError> + Send + Sync + 'a>>;
type FileSystemStopCallback<'a, T> =
    Option<Box<dyn Fn(Option<&mut T>) -> std::result::Result<(), FspError> + Send + Sync + 'a>>;
type FileSystemControlCallback<'a, T> =
    Option<Box<dyn Fn(Option<&mut T>, u32, u32, *mut c_void) -> i32 + Send + Sync + 'a>>;

struct FileSystemServiceContext<'a, T> {
    start: FileSystemStartCallback<'a, T>,
    stop: FileSystemStopCallback<'a, T>,
    control: FileSystemControlCallback<'a, T>,
    /// Holds the user-supplied filesystem context, written once by `on_start`
    /// and mutated by `on_stop` / `on_control`. The `Mutex` is mandatory:
    /// `on_start` runs on the service main thread while `on_stop` /
    /// `on_control` run on the SCM control-dispatcher thread, and
    /// user-defined controls (codes 128–255) can be dispatched concurrently
    /// with `on_start` because `dwControlsAccepted` does not gate them.
    context: Mutex<Option<T>>,
}

/// A service that runs a filesystem implemented by a [`FileSystemHost`](crate::host::FileSystemHost).
///
/// The service owns a worker thread that runs `FspServiceLoop`. The thread is
/// joined automatically on [`Drop`], so the underlying `FSP_SERVICE` is never
/// freed while a worker is still touching it.
pub struct FileSystemService<T> {
    service_ptr: NonNull<FSP_SERVICE>,
    worker: Option<JoinHandle<Result<()>>>,
    _pd: PhantomData<T>,
}

impl<T> FileSystemService<T> {
    /// Signals the file system host service to stop. The worker thread will
    /// exit shortly after this call returns; use [`join`](Self::join) (or let
    /// the service drop) to wait for it.
    pub fn stop(&self) {
        unsafe {
            FspServiceStop(self.service_ptr.as_ptr());
        };
    }

    /// Spawns the worker thread that runs `FspServiceLoop`. The handle is
    /// retained internally so [`Drop`] can join it before tearing down the
    /// `FSP_SERVICE`. Returns `STATUS_INVALID_PARAMETER` if the service is
    /// already running.
    pub fn start(&mut self) -> Result<()> {
        if self.worker.is_some() {
            return Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0));
        }
        let ptr = ServicePtr(self.service_ptr.as_ptr());
        let worker = std::thread::spawn(move || {
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
        });
        self.worker = Some(worker);
        Ok(())
    }

    /// Block until the worker thread exits and return its result.
    ///
    /// Returns `Ok(())` immediately if the service was never started or has
    /// already been joined.
    pub fn join(&mut self) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match worker.join() {
            Ok(result) => result,
            Err(_) => Err(FspError::NTSTATUS(
                windows::Win32::Foundation::EXCEPTION_NONCONTINUABLE_EXCEPTION.0,
            )),
        }
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
        F: Fn() -> std::result::Result<T, FspError> + Send + Sync + 'a,
    {
        self.start = Some(Box::new(start));
        self
    }

    /// The stop callback is responsible for safely terminating the mounted file system.
    pub fn with_stop<F>(mut self, stop: F) -> Self
    where
        F: Fn(Option<&mut T>) -> std::result::Result<(), FspError> + Send + Sync + 'a,
    {
        self.stop = Some(Box::new(stop));
        self
    }

    /// The control callback handles DeviceIoControl requests.
    pub fn with_control<F>(mut self, control: F) -> Self
    where
        F: Fn(Option<&mut T>, u32, u32, *mut c_void) -> i32 + Send + Sync + 'static,
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

        let service_ptr = unsafe { service.get().read() };
        if result != STATUS_SUCCESS.0 || service_ptr.is_null() {
            // FspServiceCreate did not produce a valid FSP_SERVICE; the
            // out pointer may be null or partially initialized, so we
            // must not write into it. Drop the prepared callbacks.
            return Err(FspError::NTSTATUS(result));
        }

        let context = Box::into_raw(Box::new(FileSystemServiceContext::<T> {
            start: self.start,
            stop: self.stop,
            control: self.control,
            context: Mutex::new(None),
        }));
        unsafe {
            (&raw mut (*service_ptr).UserContext).write(context as *mut _);
            Ok(FileSystemService {
                service_ptr: NonNull::new_unchecked(service_ptr),
                worker: None,
                _pd: PhantomData,
            })
        }
    }
}

impl<T> Drop for FileSystemService<T> {
    fn drop(&mut self) {
        // Signal the worker to stop, then wait for it to leave FspServiceLoop
        // BEFORE we free the FSP_SERVICE it's still pointing at. If we skipped
        // the join, FspServiceDelete would race with the worker thread.
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let service_context_ptr = unsafe {
            // SAFETY: FSP_SERVICE pointer and UserContext field are not mutated by other threads
            self.service_ptr.as_ref().UserContext as *mut FileSystemServiceContext<T>
        };
        unsafe {
            FspServiceDelete(self.service_ptr.as_ptr());
        };
        let service_context_box = unsafe {
            // SAFETY: worker thread has been joined and the service has been
            // deleted, so nothing else can reach the service context.
            Box::<FileSystemServiceContext<T>>::from_raw(service_context_ptr)
        };
        drop(service_context_box);
    }
}

// SAFETY (for `on_start` / `on_stop` / `on_control`): `fsp` is a valid
// `FSP_SERVICE` whose `UserContext` was populated with a
// `Box<FileSystemServiceContext<T>>` of the matching `T` by
// `FileSystemServiceBuilder::build`, and the box is alive until
// `FileSystemService::Drop` joins the worker.

unsafe extern "C" fn on_start<T>(fsp: *mut FSP_SERVICE, _argc: u32, _argv: *mut *mut u16) -> i32 {
    let Some(context) = (unsafe {
        fsp.as_ref().and_then(|fsp| {
            fsp.UserContext
                .cast::<FileSystemServiceContext<T>>()
                .as_ref()
        })
    }) else {
        return STATUS_INVALID_PARAMETER.0;
    };
    let Some(start) = context.start.as_ref() else {
        return STATUS_INVALID_PARAMETER.0;
    };
    match start() {
        Err(e) => e.to_ntstatus(),
        Ok(user_ctx) => {
            *context.context.lock() = Some(user_ctx);
            STATUS_SUCCESS.0
        }
    }
}

unsafe extern "C" fn on_stop<T>(fsp: *mut FSP_SERVICE) -> i32 {
    let Some(context) = (unsafe {
        fsp.as_ref().and_then(|fsp| {
            fsp.UserContext
                .cast::<FileSystemServiceContext<T>>()
                .as_ref()
        })
    }) else {
        return STATUS_INVALID_PARAMETER.0;
    };
    let Some(stop) = context.stop.as_ref() else {
        return STATUS_INVALID_PARAMETER.0;
    };
    let mut guard = context.context.lock();
    match stop(guard.as_mut()) {
        Ok(()) => STATUS_SUCCESS.0,
        Err(e) => e.to_ntstatus(),
    }
}

unsafe extern "C" fn on_control<T>(
    fsp: *mut FSP_SERVICE,
    ctl: u32,
    event_type: u32,
    event_data: *mut c_void,
) -> i32 {
    let Some(context) = (unsafe {
        fsp.as_ref().and_then(|fsp| {
            fsp.UserContext
                .cast::<FileSystemServiceContext<T>>()
                .as_ref()
        })
    }) else {
        return STATUS_INVALID_PARAMETER.0;
    };
    let Some(control) = context.control.as_ref() else {
        return STATUS_INVALID_PARAMETER.0;
    };
    let mut guard = context.context.lock();
    control(guard.as_mut(), ctl, event_type, event_data)
}
