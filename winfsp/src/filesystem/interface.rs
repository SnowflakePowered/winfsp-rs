use std::ffi::c_void;
use std::slice;
use widestring::U16CStr;
use windows::core::{PCWSTR, PWSTR};

use windows::Win32::Foundation::{
    EXCEPTION_NONCONTINUABLE_EXCEPTION, STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_PENDING, STATUS_REPARSE, STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES};

use winfsp_sys::{
    FspNtStatusFromWin32, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO,
};
use winfsp_sys::{NTSTATUS as FSP_STATUS, PVOID};

use crate::filesystem::{FileSecurity, FileSystemContext, IoResult};

/// Catch panic and return STATUS_INVALID_DISPOSITION
macro_rules! catch_panic {
    ($bl:block) => {
        ::std::panic::catch_unwind(|| $bl)
            .unwrap_or_else(|_| ::windows::Win32::Foundation::EXCEPTION_NONCONTINUABLE_EXCEPTION.0)
    };
}

unsafe extern "C" fn get_volume_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
        if let Some(volume_info) = unsafe { volume_info.as_mut() } {
            match T::get_volume_info(context, volume_info) {
                Ok(_) => STATUS_SUCCESS.0,
                Err(e) => as_ntstatus(e),
            }
        } else {
            EXCEPTION_NONCONTINUABLE_EXCEPTION.0
        }
    })
}

unsafe extern "C" fn get_security_by_name<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: *mut u16,
    file_attributes: *mut u32,
    security_descriptor: winfsp_sys::PSECURITY_DESCRIPTOR,
    sz_security_descriptor: *mut winfsp_sys::SIZE_T,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
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
                    STATUS_REPARSE.0
                } else {
                    STATUS_SUCCESS.0
                }
            }
            Err(e) => as_ntstatus(e),
        }
    })
}

unsafe extern "C" fn open<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: winfsp_sys::PWSTR,
    create_options: u32,
    granted_access: u32,
    out_file_context: *mut PVOID,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };

        match T::open(
            context,
            &file_name,
            create_options,
            FILE_ACCESS_FLAGS(granted_access),
            unsafe { out_file_info.as_mut().unwrap_unchecked() },
        ) {
            Ok(fctx) => {
                // expose pointer to FFI
                unsafe { *out_file_context = Box::into_raw(Box::new(fctx)) as *mut _ };
                STATUS_SUCCESS.0
            }
            Err(e) => as_ntstatus(e),
        }
    })
}

unsafe extern "C" fn create_ex<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: *mut u16,
    create_options: u32,
    granted_access: u32,
    file_attributes: u32,
    security_descriptor: PVOID,
    allocation_size: u64,
    extra_buffer: PVOID,
    extra_len: u32,
    extra_buffer_is_reparse_point: u8,
    out_fctx: *mut PVOID,
    out_finfo: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        dbg!("create_glue");
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };
        let out_finfo = unsafe { out_finfo.as_mut().unwrap_unchecked() };

        let extra_buffer = if !extra_buffer.is_null() {
            unsafe {
                Some(slice::from_raw_parts(
                    extra_buffer as *mut u8,
                    extra_len as usize,
                ))
            }
        } else {
            None
        };

        match T::create(
            context,
            file_name,
            create_options,
            FILE_ACCESS_FLAGS(granted_access),
            FILE_FLAGS_AND_ATTRIBUTES(file_attributes),
            PSECURITY_DESCRIPTOR(security_descriptor),
            allocation_size,
            extra_buffer,
            extra_buffer_is_reparse_point != 0,
            out_finfo,
        ) {
            Ok(context) => {
                unsafe { *out_fctx = Box::into_raw(Box::new(context)) as *mut _ };
                STATUS_SUCCESS.0
            }
            Err(e) => as_ntstatus(e),
        }
    })
}

unsafe extern "C" fn close<T: FileSystemContext>(fs: *mut FSP_FILE_SYSTEM, fctx: PVOID) {
    catch_panic!({
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
        let fctx = fctx.cast::<T::FileContext>();
        if !fctx.is_null() {
            // reclaim pointer from FFI
            T::close(context, unsafe { *Box::from_raw(fctx) });
        }
        0
    });
}

#[inline(always)]
fn as_ntstatus(error: windows::core::Error) -> FSP_STATUS {
    unsafe { FspNtStatusFromWin32(error.code().0 as u32) }
}

#[inline(always)]
fn require_ref<C: FileSystemContext, F>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    inner: F,
) -> FSP_STATUS
where
    F: FnOnce(&C, &mut C::FileContext) -> windows::core::Result<()>,
{
    let context: &C = unsafe { &*(*fs).UserContext.cast::<C>() };
    let fctx = fctx.cast::<C::FileContext>();

    // todo: can we unwrap_unchecked.. probably to be honest.
    if let Some(fctx) = unsafe { fctx.as_mut() } {
        match inner(context, fctx) {
            Ok(_) => STATUS_SUCCESS.0,
            Err(e) => as_ntstatus(e),
        }
    } else {
        dbg!("require_ref failed");
        STATUS_ACCESS_VIOLATION.0
    }
}

#[inline(always)]
fn require_ref_io<C: FileSystemContext, F>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    inner: F,
) -> FSP_STATUS
where
    F: FnOnce(&C, &C::FileContext) -> windows::core::Result<IoResult>,
{
    let context: &C = unsafe { &*(*fs).UserContext.cast::<C>() };
    let fctx = fctx.cast::<C::FileContext>();

    // todo: can we unwrap_unchecked.. probably to be honest.
    if let Some(fctx) = unsafe { fctx.as_ref() } {
        match inner(context, fctx) {
            Ok(res) => {
                if res.io_pending {
                    STATUS_PENDING.0
                } else {
                    STATUS_SUCCESS.0
                }
            }
            Err(e) => as_ntstatus(e),
        }
    } else {
        STATUS_ACCESS_VIOLATION.0
    }
}

unsafe extern "C" fn control<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    control_code: u32,
    input_buffer: PVOID,
    input_buffer_len: u32,
    output_buffer: PVOID,
    output_buffer_len: u32,
    pbytes_transferred: *mut u32,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| unsafe {
            let input = slice::from_raw_parts(input_buffer as *const u8, input_buffer_len as usize);
            let output =
                slice::from_raw_parts_mut(output_buffer as *mut u8, output_buffer_len as usize);
            let transferred = T::control(context, fctx, control_code, input, output)?;
            pbytes_transferred.write(transferred);
            Ok(())
        })
    })
}

unsafe extern "C" fn set_volume_label<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_label: *mut u16,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = unsafe { &*(*fs).UserContext.cast::<T>() };
        if let Some(volume_info) = unsafe { volume_info.as_mut() } {
            match T::set_volume_label(context, PWSTR::from_raw(volume_label), volume_info) {
                Ok(_) => STATUS_SUCCESS.0,
                Err(e) => as_ntstatus(e),
            }
        } else {
            EXCEPTION_NONCONTINUABLE_EXCEPTION.0
        }
    })
}

unsafe extern "C" fn overwrite<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_attributes: u32,
    replace_file_attributes: u8,
    allocation_size: u64,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let out_file_info = unsafe { &mut *out_file_info };
            T::overwrite(
                context,
                fctx,
                FILE_FLAGS_AND_ATTRIBUTES(file_attributes),
                replace_file_attributes != 0,
                allocation_size,
                out_file_info,
            )
        })
    })
}

unsafe extern "C" fn get_file_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let out_file_info = unsafe { &mut *out_file_info };
            T::get_file_info(context, fctx, out_file_info)
        })
    })
}

unsafe extern "C" fn get_security<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    security_descriptor: *mut c_void,
    out_descriptor_size: *mut u64,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let desc_size = T::get_security(
                context,
                fctx,
                PSECURITY_DESCRIPTOR(security_descriptor),
                unsafe { out_descriptor_size.as_ref().cloned() },
            )?;
            if !out_descriptor_size.is_null() {
                unsafe { out_descriptor_size.write(desc_size) }
            }
            Ok(())
        })
    })
}

unsafe extern "C" fn read_directory<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    pattern: *mut u16,
    marker: *mut u16,
    buffer: PVOID,
    buffer_len: u32,
    bytes_transferred: *mut u32,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(0) }
            }

            let pattern = if !pattern.is_null() {
                Some(PCWSTR::from_raw(pattern))
            } else {
                None
            };

            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len as usize) };

            let marker = if !marker.is_null() {
                Some(unsafe { U16CStr::from_ptr_str_mut(marker).as_slice() })
            } else {
                None
            };

            let bytes_read = T::read_directory(context, fctx, pattern, marker, buffer)?;

            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(bytes_read) }
            }
            Ok(())
        })
    })
}

unsafe extern "C" fn read<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    buffer: PVOID,
    offset: u64,
    length: u32,
    bytes_transferred: *mut u32,
) -> FSP_STATUS {
    catch_panic!({
        require_ref_io(fs, fctx, |context, fctx| {
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(0) }
            }

            if !buffer.is_null() {
                let buffer =
                    unsafe { slice::from_raw_parts_mut(buffer as *mut u8, length as usize) };
                let result = T::read(context, fctx, buffer, offset)?;
                if !bytes_transferred.is_null() {
                    unsafe { bytes_transferred.write(result.bytes_transferred) }
                }
                Ok(result)
            } else {
                Err(STATUS_INSUFFICIENT_RESOURCES.into())
            }
        })
    })
}

unsafe extern "C" fn write<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    buffer: PVOID,
    offset: u64,
    length: u32,
    write_to_eof: u8,
    constrained_io: u8,
    bytes_transferred: *mut u32,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    if out_file_info.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES.0;
    }
    catch_panic!({
        require_ref_io(fs, fctx, |context, fctx| {
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(0) }
            }

            if !buffer.is_null() {
                let buffer =
                    unsafe { slice::from_raw_parts_mut(buffer as *mut u8, length as usize) };
                let result = T::write(
                    context,
                    fctx,
                    buffer,
                    offset,
                    write_to_eof != 0,
                    constrained_io != 0,
                    unsafe { &mut *out_file_info },
                )?;
                if !bytes_transferred.is_null() {
                    unsafe { bytes_transferred.write(result.bytes_transferred) }
                }
                Ok(result)
            } else {
                Err(STATUS_INSUFFICIENT_RESOURCES.into())
            }
        })
    })
}

unsafe extern "C" fn cleanup<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    flags: u32,
) {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };
            T::cleanup(context, fctx, file_name, flags);
            Ok(())
        })
    });
}

unsafe extern "C" fn set_basic_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            T::set_basic_info(
                context,
                fctx,
                file_attributes,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                unsafe { &mut *out_file_info },
            )
        })
    })
}

unsafe extern "C" fn set_file_size<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    new_size: u64,
    set_allocation_size: u8,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            T::set_file_size(context, fctx, new_size, set_allocation_size != 0, unsafe {
                &mut *out_file_info
            })
        })
    })
}

unsafe extern "C" fn set_security<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    security_information: u32,
    modification_descriptor: *mut c_void,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            T::set_security(
                context,
                fctx,
                security_information,
                PSECURITY_DESCRIPTOR(modification_descriptor),
            )
        })
    })
}

unsafe extern "C" fn set_delete<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    delete_file: u8,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };
            T::set_delete(context, fctx, &file_name, delete_file != 0)
        })
    })
}

unsafe extern "C" fn flush<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            T::flush(context, fctx, unsafe { &mut *out_file_info })
        })
    })
}

unsafe extern "C" fn rename<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    new_file_name: *mut u16,
    replace_if_exists: u8,
) -> FSP_STATUS {
    catch_panic!({
        require_ref(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };
            let new_file_name = unsafe { U16CStr::from_ptr_str_mut(new_file_name).to_os_string() };
            T::rename(
                context,
                fctx,
                file_name,
                new_file_name,
                replace_if_exists != 0,
            )
        })
    })
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
            file_name: *mut u16,
            create_options: u32,
            granted_access: u32,
            file_context: *mut PVOID,
            file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    #[allow(clippy::type_complexity)]
    create_ex: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            file_name: *mut u16,
            create_options: u32,
            granted_access: u32,
            file_attributes: u32,
            security_descriptor: PVOID,
            allocation_size: u64,
            extra_buffer: PVOID,
            extra_len: u32,
            extra_buffer_is_reparse_point: u8,
            out_fctx: *mut PVOID,
            out_finfo: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    overwrite: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_attributes: u32,
            replace_file_attributes: u8,
            allocation_size: u64,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    control: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            control_code: u32,
            input_buffer: PVOID,
            input_buffer_len: u32,
            output_buffer: PVOID,
            output_buffer_len: u32,
            pbytes_transferred: *mut u32,
        ) -> FSP_STATUS,
    >,
    read_directory: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            pattern: *mut u16,
            marker: *mut u16,
            buffer: PVOID,
            buffer_len: u32,
            bytes_transferred: *mut u32,
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
    get_security: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            security_descriptor: *mut c_void,
            out_descriptor_size: *mut u64,
        ) -> FSP_STATUS,
    >,
    get_file_info: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    set_volume_label: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            volume_label: *mut u16,
            volume_info: *mut FSP_FSCTL_VOLUME_INFO,
        ) -> FSP_STATUS,
    >,
    read: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            buffer: PVOID,
            offset: u64,
            length: u32,
            bytes_transferred: *mut u32,
        ) -> FSP_STATUS,
    >,
    write: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            buffer: PVOID,
            offset: u64,
            length: u32,
            write_to_eof: u8,
            constrained_to: u8,
            bytes_transferred: *mut u32,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    cleanup: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            flags: u32,
        ),
    >,
    set_basic_info: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_attributes: u32,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,

    set_security: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            security_information: u32,
            modification_descriptor: *mut c_void,
        ) -> FSP_STATUS,
    >,
    set_file_size: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            new_size: u64,
            set_allocation_size: u8,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    set_delete: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            delete_file: u8,
        ) -> FSP_STATUS,
    >,
    flush: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    rename: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            new_file_name: *mut u16,
            replace_if_exists: u8,
        ) -> FSP_STATUS,
    >,
}

impl Interface {
    pub fn create<T: FileSystemContext>() -> Self {
        Interface {
            open: Some(open::<T>),
            get_security_by_name: Some(get_security_by_name::<T>),
            close: Some(close::<T>),
            create_ex: Some(create_ex::<T>),
            control: Some(control::<T>),
            overwrite: Some(overwrite::<T>),
            read_directory: Some(read_directory::<T>),
            get_volume_info: Some(get_volume_info::<T>),
            set_volume_label: Some(set_volume_label::<T>),
            get_security: Some(get_security::<T>),
            get_file_info: Some(get_file_info::<T>),
            read: Some(read::<T>),
            write: Some(write::<T>),
            cleanup: Some(cleanup::<T>),
            set_basic_info: Some(set_basic_info::<T>),
            set_file_size: Some(set_file_size::<T>),
            set_security: Some(set_security::<T>),
            set_delete: Some(set_delete::<T>),
            flush: Some(flush::<T>),
            rename: Some(rename::<T>),
        }
    }
}

impl From<Interface> for FSP_FILE_SYSTEM_INTERFACE {
    fn from(interface: Interface) -> Self {
        FSP_FILE_SYSTEM_INTERFACE {
            Open: interface.open,
            Close: interface.close,
            CreateEx: interface.create_ex,
            GetSecurityByName: interface.get_security_by_name,
            Control: interface.control,
            Overwrite: interface.overwrite,
            ReadDirectory: interface.read_directory,
            GetVolumeInfo: interface.get_volume_info,
            SetVolumeLabelW: interface.set_volume_label,
            GetSecurity: interface.get_security,
            GetFileInfo: interface.get_file_info,
            Read: interface.read,
            Write: interface.write,
            Cleanup: interface.cleanup,
            SetBasicInfo: interface.set_basic_info,
            SetFileSize: interface.set_file_size,
            SetSecurity: interface.set_security,
            SetDelete: interface.set_delete,
            Flush: interface.flush,
            Rename: interface.rename,
            ..Default::default()
        }
    }
}
