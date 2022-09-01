use crate::Result;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::thread::JoinHandle;
use windows::core::HSTRING;
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};

pub struct FileSystemService<T>(pub NonNull<FSP_SERVICE>, PhantomData<T>);

impl<T> FileSystemService<T>
{
    /// # Safety
    /// `raw` is valid and not null.
    pub unsafe fn from_raw_unchecked(raw: *mut FSP_SERVICE) -> Self {
        unsafe { FileSystemService(NonNull::new_unchecked(raw), Default::default()) }
    }

    pub fn set_context(&mut self, context: Box<T>) {
        let ptr = Box::into_raw(context);
        unsafe {
            self.0.as_mut().UserContext = ptr as *mut _;
        }
    }

    pub fn get_context(&mut self) -> Option<&mut T> {
        unsafe { self.0.as_mut().UserContext.cast::<T>().as_mut() }
    }

    pub fn stop(&self) {
        unsafe {
            FspServiceStop(self.0.as_ptr());
        };
    }
}

impl <T>FileSystemService<T>
{
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

struct AssertThreadSafe<T>(*mut T);
unsafe impl<T> Send for AssertThreadSafe<T> {}
unsafe impl<T> Sync for AssertThreadSafe<T> {}

pub struct FileSystemServiceBuilder {
    on_start: FSP_SERVICE_START,
    on_stop: FSP_SERVICE_STOP,
    on_control: FSP_SERVICE_CONTROL,
}

impl FileSystemServiceBuilder {
    pub fn new() -> Self {
        Self {
            on_stop: None,
            on_start: None,
            on_control: None,
        }
    }

    pub fn with_start(mut self, start: FSP_SERVICE_START) -> Self {
        self.on_start = start;
        self
    }

    pub fn with_stop(mut self, stop: FSP_SERVICE_STOP) -> Self {
        self.on_stop = stop;
        self
    }

    pub fn with_control(mut self, control: FSP_SERVICE_CONTROL) -> Self {
        self.on_control = control;
        self
    }

    pub fn build<T>(self, service_name: &HSTRING, _init: FspInit) -> Result<FileSystemService<T>> {
        let mut service = std::ptr::null_mut();
        let result = unsafe {
            FspServiceCreate(
                service_name.as_ptr().cast_mut(),
                self.on_start,
                self.on_stop,
                self.on_control,
                &mut service,
            )
        };

        if result == STATUS_SUCCESS.0 && !service.is_null() {
            Ok(unsafe { FileSystemService::from_raw_unchecked(service) })
        } else {
            Err(FspError::NTSTATUS(NTSTATUS(result)))
        }
    }
}

impl Default for FileSystemServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}
use crate::error::FspError;
use crate::FspInit;
pub use winfsp_sys:: FSP_SERVICE;
use winfsp_sys::{FspServiceCreate, FspServiceDelete, FspServiceLoop, FspServiceStop, FSP_SERVICE_CONTROL, FSP_SERVICE_START, FSP_SERVICE_STOP, FspServiceAllowConsoleMode};
