//! Helpful utility wrappers around OS constructs.
use crate::error::FspError;
use std::marker::PhantomData;

use std::ops::{Deref, DerefMut};

use crate::constants::MAX_PATH;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::WindowsProgramming::NtClose;

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

/// Trait that defines a method to close a Windows HANDLE.
pub trait HandleCloseHandler {
    fn close(handle: HANDLE);
}

/// Handle drop strategy for Win32 handles.
#[derive(Debug)]
pub struct Win32HandleDrop;

/// A Win32 HANDLE that is closed when it goes out of scope.
pub type Win32SafeHandle = SafeDropHandle<Win32HandleDrop>;
impl HandleCloseHandler for Win32HandleDrop {
    fn close(handle: HANDLE) {
        unsafe {
            CloseHandle(handle);
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
        if let Err(e) = unsafe { NtClose(handle) } {
            eprintln!("unable to close nt handle: {:?}", e)
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
        Self(h, PhantomData::default())
    }
}

macro_rules! win32_try {
    (unsafe $e:expr) => {
        if unsafe { !($e).as_bool() } {
            return Err($crate::error::FspError::from(unsafe {
                ::windows::Win32::Foundation::GetLastError()
            }));
        }
    };
}

// unsafe fn get_token_info<T: Default + ?Sized>(token: HANDLE, information_class: TOKEN_INFORMATION_CLASS) -> crate::Result<VariableSizedBox<T>> {
//     let mut size = unsafe {
//         let mut size = 0;
//         let res = GetTokenInformation(token, information_class, std::ptr::null_mut(), 0, &mut size).as_bool();
//         if res {
//             return Err(STATUS_INVALID_PARAMETER.into())
//         }
//
//         let res = GetLastError();
//         if res != ERROR_INSUFFICIENT_BUFFER {
//             return Err(res.into())
//         }
//         size
//     };
//
//     let mut info = VariableSizedBox::<T>::new(size as usize);
//     win32_try!(unsafe GetTokenInformation(token, information_class, info.as_mut_ptr().cast(), size, &mut size));
//
//     Ok(info)
// }
// fn sid_to_uid(sid: PSID) -> crate::Result<u32> {
//     let mut uid = 0;
//     let result = unsafe {
//         FspPosixMapSidToUid(sid.0, &mut uid)
//     };
//
//     if result != 0 {
//         return Err(FspError::NTSTATUS(NTSTATUS(result)));
//     }
//
//     Ok(uid)
// }

/// Get the security descriptor of the current process.
///
/// This is often used to have virtualized directories 'inherit' the security of the filesystem host
/// process.
pub fn get_process_security(
    security_descriptor: PSECURITY_DESCRIPTOR,
    len: Option<u32>,
) -> crate::Result<u32> {
    let mut path = [0u16; MAX_PATH];
    unsafe {
        GetModuleFileNameW(None, &mut path);
    };

    let handle = unsafe {
        let handle = CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        if handle.is_invalid() {
            return Err(FspError::from(GetLastError()));
        }
        handle
    };

    let mut descriptor_len_needed = 0;
    win32_try!(unsafe GetKernelObjectSecurity(
        handle,
        (OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION)
            .0,
        security_descriptor,
        len.unwrap_or(0),
        &mut descriptor_len_needed,
    ));

    Ok(descriptor_len_needed)
}

#[cfg(all(test, target_os = "windows"))]
mod test {
    use crate::util::get_process_security;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    #[test]
    fn test_get_user_security() {
        crate::winfsp_init_or_die();
        eprintln!("hello");

        let _ = get_process_security(PSECURITY_DESCRIPTOR::default(), None);
    }
}

pub use crate::vsb::VariableSizedBox;
