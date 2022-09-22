use crate::filesystem::FileSystemContext;
use std::pin::Pin;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{
    CreateThreadpoolTimer, SetThreadpoolTimer, TP_CALLBACK_INSTANCE, TP_TIMER,
};
use winfsp_sys::FSP_FILE_SYSTEM;
use crate::filesystem::notify::Notifier;

pub struct Timer(*mut TP_TIMER);

impl Timer {
    pub fn create<T: FileSystemContext>(fs: *mut FSP_FILE_SYSTEM, period: u32) {
        let mut timer = Self(std::ptr::null_mut());
        timer.0 = unsafe {
            CreateThreadpoolTimer(Some(timer_callback::<T>), fs.cast(), std::ptr::null_mut())
        };

        let timer_due = period as i64 * -1;
        unsafe {
            SetThreadpoolTimer(timer.0, &timer_due as *const i64 as *const _, period, 0);
        }
    }
}

pub fn timer_callback<T: FileSystemContext>(
    instance: *mut TP_CALLBACK_INSTANCE,
    context: *mut core::ffi::c_void,
    timer: *mut TP_TIMER,
) {
    let fs = context.cast::<FSP_FILE_SYSTEM>();
    let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
    let notifier = Notifier(fs);
    todo!();
}
