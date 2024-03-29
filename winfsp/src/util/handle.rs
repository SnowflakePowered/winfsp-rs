use std::marker::PhantomData;

use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicIsize, Ordering};

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
pub struct SafeDropHandle<T>(HANDLE, PhantomData<T>)
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
pub struct AtomicHandle<T>(AtomicIsize, PhantomData<T>)
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
        if !self.is_invalid() {
            T::close(self.0)
        }
        self.0 = INVALID_HANDLE_VALUE
    }
}

impl<T> Drop for SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    fn drop(&mut self) {
        if !self.is_invalid() {
            T::close(self.0)
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
    pub fn handle(&self) -> HANDLE {
        let handle = self.0.load(Ordering::Acquire);
        HANDLE(handle)
    }

    /// Whether or not this handle is invalid.
    pub fn is_invalid(&self) -> bool {
        self.handle().is_invalid()
    }

    /// Invalidate the handle without dropping it.
    pub fn invalidate(&self) {
        let handle = self.handle();

        if !handle.is_invalid() {
            T::close(handle)
        }
        self.0.store(INVALID_HANDLE_VALUE.0, Ordering::Relaxed);
    }
}

impl<T> Deref for SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<HANDLE> for SafeDropHandle<T>
where
    T: HandleCloseHandler,
{
    fn from(h: HANDLE) -> Self {
        Self(h, PhantomData)
    }
}

impl<T> From<HANDLE> for AtomicHandle<T>
where
    T: HandleCloseHandler,
{
    fn from(h: HANDLE) -> Self {
        Self(AtomicIsize::new(h.0), PhantomData)
    }
}

impl<T> From<SafeDropHandle<T>> for AtomicHandle<T>
where
    T: HandleCloseHandler,
{
    fn from(h: SafeDropHandle<T>) -> Self {
        // forbid SafeDropHandle from running `Drop`
        let h = ManuallyDrop::new(h);
        Self(AtomicIsize::new(h.0 .0), PhantomData)
    }
}
