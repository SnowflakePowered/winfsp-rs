use crate::host::interface::FileSystemUserContext;
use crate::notify::{Notifier, NotifyingFileSystemContext};
use std::ptr::NonNull;
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
use windows::Win32::System::Threading::{
    CloseThreadpoolTimer, CreateThreadpoolTimer, PTP_CALLBACK_INSTANCE, PTP_TIMER,
    SetThreadpoolTimer,
};
use windows::core::Result;
use winfsp_sys::{FSP_FILE_SYSTEM, FspFileSystemNotifyBegin, FspFileSystemNotifyEnd};

pub struct Timer(PTP_TIMER);

impl Timer {
    pub fn create<R, T: NotifyingFileSystemContext<R>, const TIMEOUT: u32>(
        fs: NonNull<FSP_FILE_SYSTEM>,
    ) -> Result<Self> {
        let mut timer = Self(PTP_TIMER::default());
        timer.0 = unsafe {
            CreateThreadpoolTimer(
                Some(timer_callback::<R, T, TIMEOUT>),
                Some(fs.as_ptr().cast()),
                None,
            )?
        };

        let timer_due = -(TIMEOUT as i64);
        unsafe {
            SetThreadpoolTimer(
                timer.0,
                Some(&timer_due as *const i64 as *const _),
                TIMEOUT,
                Some(0),
            );
        }
        Ok(timer)
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        unsafe { CloseThreadpoolTimer(self.0) }
    }
}

unsafe extern "system" fn timer_callback<
    R,
    T: NotifyingFileSystemContext<R>,
    const TIMEOUT: u32,
>(
    _instance: PTP_CALLBACK_INSTANCE,
    context: *mut core::ffi::c_void,
    _timer: PTP_TIMER,
) {
    let fs = context.cast::<FSP_FILE_SYSTEM>();
    if fs.is_null() {
        panic!("Timer callback was passed in a null pointer")
    }
    let context: &FileSystemUserContext<T> =
        unsafe { &*(*fs).UserContext.cast::<FileSystemUserContext<T>>() };
    let notifier = Notifier(fs);
    if let Some(val) = context.should_notify() {
        unsafe {
            if NTSTATUS(FspFileSystemNotifyBegin(fs, TIMEOUT)) == STATUS_SUCCESS {
                context.notify(val, &notifier)
            };
            FspFileSystemNotifyEnd(fs);
        }
    }
}
