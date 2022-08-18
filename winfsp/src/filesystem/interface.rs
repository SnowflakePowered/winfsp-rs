use widestring::U16CStr;

use windows::Win32::Foundation::{
    EXCEPTION_NONCONTINUABLE_EXCEPTION, STATUS_REPARSE, STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::FILE_ACCESS_FLAGS;

use winfsp_sys::{
    FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO,
};
use winfsp_sys::{NTSTATUS as FSP_STATUS, PVOID};

use crate::filesystem::{FileSecurity, FileSystemContext};

/// Catch panic and return STATUS_INVALID_DISPOSITION
macro_rules! catch_panic {
    ($bl:block) => {
        ::std::panic::catch_unwind(|| $bl)
            .unwrap_or_else(|_| ::windows::Win32::Foundation::EXCEPTION_NONCONTINUABLE_EXCEPTION.0)
    };
}

pub unsafe extern "C" fn get_volume_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = unsafe { (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked() };
        if let Some(volume_info) = unsafe { volume_info.as_mut() } {
            match T::get_volume_info(context, volume_info) {
                Ok(_) => {
                    dbg!(STATUS_SUCCESS);
                    STATUS_SUCCESS
                }
                .into(),
                Err(e) => e.code(),
            }
            .0
        } else {
            EXCEPTION_NONCONTINUABLE_EXCEPTION.0
        }
    })
}

pub unsafe extern "C" fn get_security_by_name<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: winfsp_sys::PWSTR,
    file_attributes: winfsp_sys::PUINT32,
    security_descriptor: winfsp_sys::PSECURITY_DESCRIPTOR,
    sz_security_descriptor: *mut winfsp_sys::SIZE_T,
) -> FSP_STATUS {
    dbg!("get_security_by_name");
    catch_panic!({
        let context: &T = unsafe { (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked() };
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };
        match T::get_security_by_name(
            context,
            file_name,
            PSECURITY_DESCRIPTOR(security_descriptor),
            unsafe { sz_security_descriptor.as_ref() }.cloned(),
        ) {
            Ok(FileSecurity {
                attributes,
                reparse,
                sz_security_descriptor: len_desc,
            }) => {
                if !file_attributes.is_null() {
                    unsafe { file_attributes.write(attributes) }
                }
                if !sz_security_descriptor.is_null() {
                    unsafe { sz_security_descriptor.write(len_desc) }
                }
                if reparse {
                    STATUS_REPARSE.into()
                } else {
                    STATUS_SUCCESS.into()
                }
            }
            Err(e) => e.code(),
        }
        .0
    })
}

pub unsafe extern "C" fn open<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: winfsp_sys::PWSTR,
    create_options: u32,
    granted_access: u32,
    file_context: *mut PVOID,
    file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    dbg!("open");
    catch_panic!({
        let context: &T = unsafe { (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked() };
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };

        match T::open(
            context,
            &file_name,
            create_options,
            FILE_ACCESS_FLAGS(granted_access),
            unsafe { file_info.as_mut().unwrap_unchecked() },
        ) {
            Ok(context) => {
                // expose pointer to FFI
                unsafe { *file_context = Box::into_raw(Box::new(context)) as *mut _ };
                STATUS_SUCCESS.into()
            }
            Err(e) => e.code(),
        }
        .0
    })
}

pub unsafe extern "C" fn close<T: FileSystemContext>(fs: *mut FSP_FILE_SYSTEM, fptr: PVOID) {
    dbg!("close");
    catch_panic!({
        let context: &T = unsafe { (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked() };
        let fptr = fptr.cast::<T::FileContext>();
        if !fptr.is_null() {
            // reclaim pointer from FFI
            T::close(context, unsafe { *Box::from_raw(fptr) });
        }
        0
    });
}



pub struct Interface {
    get_volume_info: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            volume_info: *mut FSP_FSCTL_VOLUME_INFO,
        ) -> FSP_STATUS,
    >,
    close: Option<unsafe extern "C" fn(fs: *mut FSP_FILE_SYSTEM, fptr: PVOID)>,
    open: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            file_name: winfsp_sys::PWSTR,
            create_options: u32,
            granted_access: u32,
            file_context: *mut PVOID,
            file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    get_security_by_name: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            file_name: winfsp_sys::PWSTR,
            file_attributes: winfsp_sys::PUINT32,
            security_descriptor: winfsp_sys::PSECURITY_DESCRIPTOR,
            sz_security_descriptor: *mut winfsp_sys::SIZE_T,
        ) -> FSP_STATUS,
    >,
}

impl Interface {
    pub fn create<T: FileSystemContext>() -> Self {
        Interface {
            get_volume_info: Some(get_volume_info::<T>),
            close: Some(close::<T>),
            open: Some(open::<T>),
            get_security_by_name: Some(get_security_by_name::<T>),
        }
    }
}

impl From<Interface> for FSP_FILE_SYSTEM_INTERFACE {
    fn from(interface: Interface) -> Self {
        FSP_FILE_SYSTEM_INTERFACE {
            GetVolumeInfo: interface.get_volume_info,
            Close: interface.close,
            Open: interface.open,
            GetSecurityByName: interface.get_security_by_name,
            ..Default::default()
        }
    }
}
