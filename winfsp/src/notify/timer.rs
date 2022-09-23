use crate::notify::{Notifier, NotifyingFileSystemContext};
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
use windows::Win32::System::Threading::{
    CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, TP_CALLBACK_INSTANCE, TP_TIMER,
};
use winfsp_sys::{FspFileSystemNotifyBegin, FspFileSystemNotifyEnd, FSP_FILE_SYSTEM};

pub struct Timer(*mut TP_TIMER);

impl Timer {
    pub fn create<R, T: NotifyingFileSystemContext<R>, const TIMEOUT: u32>(
        fs: *mut FSP_FILE_SYSTEM,
    ) -> Self {
        let mut timer = Self(std::ptr::null_mut());
        timer.0 = unsafe {
            CreateThreadpoolTimer(
                Some(timer_callback::<R, T, TIMEOUT>),
                Some(fs.cast()),
                None,
            )
        };

        let timer_due = TIMEOUT as i64 * -1;
        unsafe {
            SetThreadpoolTimer(timer.0, Some(&timer_due as *const i64 as *const _), TIMEOUT, 0);
        }
        timer
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        unsafe { CloseThreadpoolTimer(self.0) }
    }
}

extern "system" fn timer_callback<R, T: NotifyingFileSystemContext<R>, const TIMEOUT: u32>(
    _instance: *mut TP_CALLBACK_INSTANCE,
    context: *mut core::ffi::c_void,
    _timer: *mut TP_TIMER,
) {
    let fs = context.cast::<FSP_FILE_SYSTEM>();
    let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
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
