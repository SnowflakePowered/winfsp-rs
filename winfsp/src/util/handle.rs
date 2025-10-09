use std::ffi::c_void;
use std::marker::PhantomData;

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows::Wdk::Foundation::NtClose;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// An owned handle that will always be dropped when it goes out of scope.
///
/// ## Safety
/// This handle will become invalid when it goes out of scope.
/// `SafeDropHandle` implements `Deref<Target=HANDLE>` to make it
/// usable for APIs that take `HANDLE`. Dereference the `SafeDropHandle`
/// to obtain a `HANDLE` that is `Copy` without dropping the `SafeDropHandle`
/// and invalidating the underlying handle.
#[repr(transparent)]
#[derive(Debug)]
pub struct SafeDropHandle<T>(*mut c_void, PhantomData<T>)
where
    T: HandleCloseHandler;

/// A handle that can be atomically invalidated.
///
/// ## Safety
/// This handle will become invalid when it goes out of scope.
/// Use [`AtomicHandle::handle`](AtomicHandle::handle) to obtain a `HANDLE` that is `Copy`
/// without dropping the `AtomicHandle` and invalidating the underlying handle.
#[repr(transparent)]
#[derive(Debug)]
pub struct AtomicHandle<T>(AtomicPtr<c_void>, PhantomData<T>)
where
    T: HandleCloseHandler;

/// Trait that defines a method to close a Windows HANDLE.
pub trait HandleCloseHandler {
    /// Close the handle.
    fn close(handle: HANDLE);
}

/// Handle drop strategy for Win32 handles.
#[derive(Debug)]
pub struct Win32HandleDrop;

/// A Win32 HANDLE that is closed when it goes out of scope.
pub type Win32SafeHandle = SafeDropHandle<Win32HandleDrop>;
impl HandleCloseHandler for Win32HandleDrop {
    fn close(handle: HANDLE) {
        if let Err(e) = unsafe { CloseHandle(handle) } {
            eprintln!("unable to close win32 handle {:x?}: {:?}", handle, e)
        }
    }
}

/// Handle drop strategy for NT handles.
#[derive(Debug)]
pub struct NtHandleDrop;
/// An NT HANDLE that is closed when it goes out of scope.
pub type NtSafeHandle = SafeDropHandle<NtHandleDrop>;
impl HandleCloseHandler for NtHandleDrop {
    fn close(handle: HANDLE) {
        if let Err(e) = unsafe { NtClose(handle).ok() } {
            eprintln!("unable to close nt handle {:x?}: {:?}", handle, e)
        }
    }
}

impl<T> SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    /// Invalidate the handle without dropping it.
    pub fn invalidate(&mut self) {
        if !HANDLE(self.0).is_invalid() {
            T::close(HANDLE(self.0))
        }
        self.0 = INVALID_HANDLE_VALUE.0
    }

    /// Return the inner handle.
    pub fn handle(&self) -> *mut c_void {
        self.0
    }
}

impl<T> Drop for SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    fn drop(&mut self) {
        if !HANDLE(self.0).is_invalid() {
            T::close(HANDLE(self.0))
        }
    }
}

impl<T> Drop for AtomicHandle<T>
where
    T: HandleCloseHandler,
{
    fn drop(&mut self) {
        let handle = HANDLE(self.0.load(Ordering::Acquire));
        if !handle.is_invalid() {
            T::close(handle)
        }
    }
}

impl<T> AtomicHandle<T>
where
    T: HandleCloseHandler,
{
    /// Atomically load the handle with acquire ordering
    pub fn handle(&self) -> *mut c_void {
        let handle = self.0.load(Ordering::Acquire);
        handle
    }

    /// Invalidate the handle without dropping it.
    pub fn invalidate(&self) {
        let handle = self.handle();

        if !HANDLE(handle).is_invalid() {
            T::close(HANDLE(handle))
        }
        self.0.store(INVALID_HANDLE_VALUE.0, Ordering::Relaxed);
    }
}

impl<T> From<SafeDropHandle<T>> for AtomicHandle<T>
where
    T: HandleCloseHandler,
{
    fn from(h: SafeDropHandle<T>) -> Self {
        // forbid SafeDropHandle from running `Drop`
        let h = ManuallyDrop::new(h);
        Self(AtomicPtr::new(h.0), PhantomData)
    }
}

/// Trait to access the inner handle
pub trait HandleInnerMut<T> {
    /// Return a mutable borrow to the inner handle.
    fn handle_mut(&mut self) -> &mut T;
}

macro_rules! windows_rs_handle {
    ($windows_crate:ident, $module_name:ident) => {
        mod $module_name {
            use crate::util::{AtomicHandle, HandleCloseHandler, SafeDropHandle};
            use std::marker::PhantomData;
            use std::sync::atomic::AtomicPtr;
            use $windows_crate as windows;

            impl<T> super::HandleInnerMut<windows::Win32::Foundation::HANDLE> for SafeDropHandle<T>
            where
                T: HandleCloseHandler,
            {
                fn handle_mut(&mut self) -> &mut windows::Win32::Foundation::HANDLE {
                    // SAFETY: HANDLE is a transparent wrapper.
                    unsafe { ::std::mem::transmute(&mut self.0) }
                }
            }

            impl<T> From<windows::Win32::Foundation::HANDLE> for SafeDropHandle<T>
            where
                T: HandleCloseHandler,
            {
                fn from(h: windows::Win32::Foundation::HANDLE) -> Self {
                    Self(h.0 as *mut ::std::ffi::c_void, PhantomData)
                }
            }

            impl<T> From<windows::Win32::Foundation::HANDLE> for AtomicHandle<T>
            where
                T: HandleCloseHandler,
            {
                fn from(h: windows::Win32::Foundation::HANDLE) -> Self {
                    Self(AtomicPtr::new(h.0 as *mut ::std::ffi::c_void), PhantomData)
                }
            }
        }
    };
}

windows_rs_handle!(windows, windows_rs_handle);

#[cfg(feature = "windows-56")]
windows_rs_handle!(windows_56, windows_56_rs_handle);

#[cfg(feature = "windows-60")]
windows_rs_handle!(windows_60, windows_60_rs_handle);

#[cfg(feature = "windows-62")]
windows_rs_handle!(windows_62, windows_62_rs_handle);
