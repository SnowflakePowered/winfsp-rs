use std::ffi::c_void;
use std::slice;
use windows::core::PWSTR;

use windows::Win32::Foundation::{
    EXCEPTION_NONCONTINUABLE_EXCEPTION, STATUS_INSUFFICIENT_RESOURCES, STATUS_PENDING,
    STATUS_REPARSE, STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES};

use crate::{error, U16CStr};
use winfsp_sys::{
    FspFileSystemFindReparsePoint, FspFileSystemResolveReparsePoints, BOOLEAN, FSP_FILE_SYSTEM,
    FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_DIR_INFO, FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO,
    PFILE_FULL_EA_INFORMATION, PIO_STATUS_BLOCK, PSIZE_T,
};
use winfsp_sys::{NTSTATUS as FSP_STATUS, PVOID};

use crate::filesystem::{DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, IoResult, OpenFileInfo, VolumeInfo};

/// Catch panic and return EXECPTION_NONCONTINUABLE_EXCEPTION
macro_rules! catch_panic {
    ($bl:block) => {
        ::std::panic::catch_unwind(|| $bl)
            .unwrap_or_else(|_| ::windows::Win32::Foundation::EXCEPTION_NONCONTINUABLE_EXCEPTION.0)
    };
}

macro_rules! assert_ctx {
    ($fs:expr) => {
        if $fs.is_null() {
            panic!("Received null {} context!", ::std::stringify!($fs));
        }
    };
    ($fs:expr, $tag:expr) => {
        if $fs.is_null() {
            panic!("Received null {} context: {}", ::std::stringify!($fs), $tag);
        }
    };
}

#[inline(always)]
fn require_fctx<C: FileSystemContext, F>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    inner: F,
) -> FSP_STATUS
where
    F: FnOnce(&C, &mut C::FileContext) -> error::Result<()>,
{
    assert_ctx!(fs);
    assert_ctx!(fctx);

    let context: &C = unsafe { &*(*fs).UserContext.cast::<C>() };
    let fctx = unsafe { &mut *fctx.cast::<C::FileContext>() };

    match inner(context, fctx) {
        Ok(_) => STATUS_SUCCESS.0,
        Err(e) => e.as_ntstatus(),
    }
}

#[inline(always)]
fn require_ctx<C: FileSystemContext, F>(fs: *mut FSP_FILE_SYSTEM, inner: F) -> FSP_STATUS
where
    F: FnOnce(&C) -> error::Result<()>,
{
    assert_ctx!(fs);

    let context: &C = unsafe { &*(*fs).UserContext.cast::<C>() };
    match inner(context) {
        Ok(_) => STATUS_SUCCESS.0,
        Err(e) => e.as_ntstatus(),
    }
}

#[inline(always)]
fn require_fctx_io<C: FileSystemContext, F>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    inner: F,
) -> FSP_STATUS
where
    F: FnOnce(&C, &C::FileContext) -> error::Result<IoResult>,
{
    assert_ctx!(fs);
    assert_ctx!(fctx);

    let context: &C = unsafe { &*(*fs).UserContext.cast::<C>() };
    let fctx = unsafe { &mut *fctx.cast::<C::FileContext>() };

    match inner(context, fctx) {
        Ok(res) => {
            if res.io_pending {
                STATUS_PENDING.0
            } else {
                STATUS_SUCCESS.0
            }
        }
        Err(e) => e.as_ntstatus(),
    }
}

unsafe extern "C" fn get_volume_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ctx(fs, |context| {
            // SAFETY: VolumeInfo has the same layout (align, size) as FSP_FSCTL_VOLUME_INFO
            if let Some(volume_info) = unsafe { volume_info.cast::<VolumeInfo>().as_mut() } {
                T::get_volume_info(context, volume_info)
            } else {
                Err(EXCEPTION_NONCONTINUABLE_EXCEPTION.into())
            }
        })
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
        if file_name.is_null() {
            panic!("gsbn: filename is null")
        }
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };

        // pass reparse point resolver into function
        let find_reparse_points = |file_name: &U16CStr| {
            let mut reparse_index = 0;
            unsafe {
                if FspFileSystemFindReparsePoint(
                    fs,
                    Some(get_reparse_point_by_name::<T>),
                    std::ptr::null_mut(),
                    file_name.as_ptr().cast_mut(),
                    &mut reparse_index,
                ) != 0
                {
                    Some(reparse_index)
                } else {
                    None
                }
            }
        };

        match T::get_security_by_name(
            context,
            file_name,
            PSECURITY_DESCRIPTOR(security_descriptor),
            unsafe { sz_security_descriptor.as_ref() }.cloned(),
            find_reparse_points,
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
            Err(e) => e.as_ntstatus(),
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
        require_ctx(fs, |context| {
            if file_name.is_null() {
                panic!("open: filename is null")
            }
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let fctx = T::open(
                context,
                file_name,
                create_options,
                FILE_ACCESS_FLAGS(granted_access),
                // SAFETY: https://winfsp.dev/doc/WinFsp-API-winfsp.h/
                // The FileInfo parameter to Create and Open is typed as pointer to FSP_FSCTL_FILE_INFO.
                // The true type of this parameter is pointer to FSP_FSCTL_OPEN_FILE_INFO.
                unsafe { out_file_info.cast::<OpenFileInfo>().as_mut() }
                    .expect("FSP_FSCTL_FILE_INFO buffer was not allocated."),
            )?;
            unsafe { *out_file_context = Box::into_raw(Box::new(fctx)) as *mut _ };
            Ok(())
        })
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
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_ctx(fs, |context| {
            if file_name.is_null() {
                panic!("create: filename is null")
            }
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
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

            let fctx = T::create(
                context,
                file_name,
                create_options,
                FILE_ACCESS_FLAGS(granted_access),
                FILE_FLAGS_AND_ATTRIBUTES(file_attributes),
                PSECURITY_DESCRIPTOR(security_descriptor),
                allocation_size,
                extra_buffer,
                extra_buffer_is_reparse_point != 0,
                // SAFETY: https://winfsp.dev/doc/WinFsp-API-winfsp.h/
                // The FileInfo parameter to Create and Open is typed as pointer to FSP_FSCTL_FILE_INFO.
                // The true type of this parameter is pointer to FSP_FSCTL_OPEN_FILE_INFO.
                unsafe { out_file_info.cast::<OpenFileInfo>().as_mut() }
                    .expect("FSP_FSCTL_FILE_INFO buffer was not allocated."),
            )?;
            unsafe { *out_fctx = Box::into_raw(Box::new(fctx)) as *mut _ };
            Ok(())
        })
    })
}

unsafe extern "C" fn close<T: FileSystemContext>(fs: *mut FSP_FILE_SYSTEM, fctx: PVOID) {
    if fctx.is_null() {
        return;
    }
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            T::close(context, unsafe { *Box::from_raw(fctx) });
            Ok(())
        })
    });
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
        require_fctx(fs, fctx, |context, fctx| unsafe {
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
        if let Some(volume_info) = unsafe { volume_info.cast::<VolumeInfo>().as_mut() } {
            require_ctx(fs, |context| {
                T::set_volume_label(context, PWSTR::from_raw(volume_label), volume_info)
            })
        } else {
            EXCEPTION_NONCONTINUABLE_EXCEPTION.0
        }
    })
}

unsafe extern "C" fn overwrite_ex<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_attributes: u32,
    replace_file_attributes: u8,
    allocation_size: u64,
    extra_buffer: PFILE_FULL_EA_INFORMATION,
    extra_len: u32,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let out_file_info = unsafe { &mut *out_file_info.cast::<FileInfo>() };
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

            T::overwrite(
                context,
                fctx,
                FILE_FLAGS_AND_ATTRIBUTES(file_attributes),
                replace_file_attributes != 0,
                allocation_size,
                extra_buffer,
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
        require_fctx(fs, fctx, |context, fctx| {
            T::get_file_info(context, fctx, unsafe {
                out_file_info
                    .cast::<FileInfo>()
                    .as_mut()
                    .expect("FSP_FSCTL_FILE_INFO buffer was not allocated.")
            })
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
        require_fctx(fs, fctx, |context, fctx| {
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
        require_fctx(fs, fctx, |context, fctx| {
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(0) }
            }

            let pattern = if !pattern.is_null() {
                Some(unsafe { U16CStr::from_ptr_str(pattern) })
            } else {
                None
            };

            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len as usize) };

            let marker = if !marker.is_null() {
                Some(unsafe { U16CStr::from_ptr_str(marker) })
            } else {
                None
            };

            let bytes_read = T::read_directory(context, fctx, pattern, DirMarker(marker), buffer)?;

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
        require_fctx_io(fs, fctx, |context, fctx| {
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
        require_fctx_io(fs, fctx, |context, fctx| {
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
                    unsafe { out_file_info.cast::<FileInfo>().as_mut() }
                        .expect("FSP_FSCTL_FILE_INFO buffer was not allocated."),
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
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = if !file_name.is_null() {
                Some(unsafe { U16CStr::from_ptr_str_mut(file_name) })
            } else {
                None
            };
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
        require_fctx(fs, fctx, |context, fctx| {
            T::set_basic_info(
                context,
                fctx,
                file_attributes,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                unsafe { out_file_info.cast::<FileInfo>().as_mut() }
                    .expect("FSP_FSCTL_FILE_INFO buffer was not allocated."),
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
        require_fctx(fs, fctx, |context, fctx| {
            T::set_file_size(
                context,
                fctx,
                new_size,
                set_allocation_size != 0,
                unsafe { out_file_info.cast::<FileInfo>().as_mut() }
                    .expect("FSP_FSCTL_FILE_INFO buffer was not allocated."),
            )
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
        require_fctx(fs, fctx, |context, fctx| {
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
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
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
        require_ctx(fs, |context| {
            let fctx = fctx.cast::<T::FileContext>();
            unsafe { T::flush(context, fctx.as_ref(), &mut *out_file_info.cast::<FileInfo>()) }
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
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let new_file_name = unsafe { U16CStr::from_ptr_str_mut(new_file_name) };
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

unsafe extern "C" fn get_ea<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    ea: PFILE_FULL_EA_INFORMATION,
    ea_len: u32,
    psize: *mut u32,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let buffer = unsafe { slice::from_raw_parts_mut(ea.cast::<u8>(), ea_len as usize) };
            let bytes_transferred = T::get_extended_attributes(context, fctx, buffer)?;
            if !psize.is_null() {
                unsafe { psize.write(bytes_transferred) };
            }
            Ok(())
        })
    })
}

unsafe extern "C" fn set_ea<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    ea: PFILE_FULL_EA_INFORMATION,
    ea_len: u32,
    out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let buffer = unsafe { slice::from_raw_parts(ea.cast::<u8>(), ea_len as usize) };
            unsafe { T::set_extended_attributes(context, fctx, buffer, &mut *out_file_info.cast::<FileInfo>()) }
        })
    })
}

unsafe extern "C" fn get_reparse_point_by_name<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    _ctx: PVOID,
    file_name: *mut u16,
    is_directory: u8,
    buffer: PVOID,
    psize: PSIZE_T,
) -> FSP_STATUS {
    catch_panic!({
        require_ctx(fs, |context| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let buffer_len = unsafe { psize.read() };
            if !buffer.is_null() {
                let buffer =
                    unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_len as usize) };
                let bytes_transferred =
                    T::get_reparse_point_by_name(context, file_name, is_directory != 0, buffer)?;
                if !psize.is_null() {
                    unsafe { psize.write(bytes_transferred) };
                }
            } else {
                // sometimes GetReparsePointByName is called with a null buffer, in
                // cases where the caller does not care about the result.
                let mut buffer = vec![0u8; crate::constants::FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX];
                let bytes_transferred = T::get_reparse_point_by_name(
                    context,
                    file_name,
                    is_directory != 0,
                    &mut buffer,
                )?;
                if !psize.is_null() {
                    unsafe { psize.write(bytes_transferred) };
                }
            }

            Ok(())
        })
    })
}

unsafe extern "C" fn resolve_reparse_points<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: *mut u16,
    reparse_point_index: u32,
    resolve_last_component: BOOLEAN,
    io_status: PIO_STATUS_BLOCK,
    buffer: PVOID,
    psize: PSIZE_T,
) -> FSP_STATUS {
    unsafe {
        FspFileSystemResolveReparsePoints(
            fs,
            Some(get_reparse_point_by_name::<T>),
            std::ptr::null_mut(),
            file_name,
            reparse_point_index,
            resolve_last_component,
            io_status,
            buffer,
            psize,
        )
    }
}

unsafe extern "C" fn get_reparse_point<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    buffer: PVOID,
    psize: PSIZE_T,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let buffer_len = unsafe { psize.read() };
            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_len as usize) };
            let bytes_transferred = T::get_reparse_point(context, fctx, file_name, buffer)?;

            if !psize.is_null() {
                unsafe { psize.write(bytes_transferred) };
            }
            Ok(())
        })
    })
}

unsafe extern "C" fn set_reparse_point<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    buffer: PVOID,
    buffer_len: u64,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_len as usize) };
            T::set_reparse_point(context, fctx, file_name, buffer)?;
            Ok(())
        })
    })
}

unsafe extern "C" fn delete_reparse_point<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    buffer: PVOID,
    buffer_len: u64,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_len as usize) };
            T::delete_reparse_point(context, fctx, file_name, buffer)?;
            Ok(())
        })
    })
}

unsafe extern "C" fn get_stream_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    buffer: PVOID,
    buffer_len: u32,
    bytes_transferred: *mut u32,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(0) }
            }

            let buffer =
                unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len as usize) };
            let bytes_read = T::get_stream_info(context, fctx, buffer)?;
            if !bytes_transferred.is_null() {
                unsafe { bytes_transferred.write(bytes_read) }
            }
            Ok(())
        })
    })
}

unsafe extern "C" fn get_dir_info_by_name<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    file_name: *mut u16,
    dir_info: *mut FSP_FSCTL_DIR_INFO,
) -> FSP_STATUS {
    catch_panic!({
        require_fctx(fs, fctx, |context, fctx| {
            let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name) };
            if dir_info.is_null() {
                panic!("get_dir_info_by_name was passed a null dirinfo buffer.")
            }

            let buffer = dir_info.cast::<DirInfo>();
            T::get_dir_info_by_name(context, fctx, file_name, unsafe {
                buffer.as_mut().unwrap()
            })
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
    overwrite_ex: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_attributes: u32,
            replace_file_attributes: u8,
            allocation_size: u64,
            extra_buffer: PFILE_FULL_EA_INFORMATION,
            extra_len: u32,
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
    get_ea: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            ea: PFILE_FULL_EA_INFORMATION,
            ea_len: u32,
            bytes_transferred: *mut u32,
        ) -> FSP_STATUS,
    >,
    set_ea: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            ea: PFILE_FULL_EA_INFORMATION,
            ea_len: u32,
            out_file_info: *mut FSP_FSCTL_FILE_INFO,
        ) -> FSP_STATUS,
    >,
    get_reparse_point: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            buffer: PVOID,
            psize: PSIZE_T,
        ) -> FSP_STATUS,
    >,
    set_reparse_point: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            buffer: PVOID,
            buffer_len: u64,
        ) -> FSP_STATUS,
    >,
    delete_reparse_point: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            buffer: PVOID,
            buffer_len: u64,
        ) -> FSP_STATUS,
    >,
    resolve_reparse_points: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            file_name: *mut u16,
            reparse_point_index: u32,
            resolve_last_component: BOOLEAN,
            io_status: PIO_STATUS_BLOCK,
            buffer: PVOID,
            psize: PSIZE_T,
        ) -> FSP_STATUS,
    >,
    get_stream_info: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            buffer: PVOID,
            buffer_len: u32,
            bytes_transferred: *mut u32,
        ) -> FSP_STATUS,
    >,
    get_dir_info_by_name: Option<
        unsafe extern "C" fn(
            fs: *mut FSP_FILE_SYSTEM,
            fctx: PVOID,
            file_name: *mut u16,
            dir_info: *mut FSP_FSCTL_DIR_INFO,
        ) -> FSP_STATUS,
    >,
}

impl Interface {
    pub(crate) fn create_with_read_directory<T: FileSystemContext>() -> Self {
        Interface {
            open: Some(open::<T>),
            get_security_by_name: Some(get_security_by_name::<T>),
            close: Some(close::<T>),
            create_ex: Some(create_ex::<T>),
            control: Some(control::<T>),
            overwrite_ex: Some(overwrite_ex::<T>),
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
            get_ea: Some(get_ea::<T>),
            set_ea: Some(set_ea::<T>),
            get_reparse_point: Some(get_reparse_point::<T>),
            set_reparse_point: Some(set_reparse_point::<T>),
            delete_reparse_point: Some(delete_reparse_point::<T>),
            resolve_reparse_points: Some(resolve_reparse_points::<T>),
            get_stream_info: Some(get_stream_info::<T>),
            get_dir_info_by_name: None,
        }
    }

    pub(crate) fn create_with_dirinfo_by_name<T: FileSystemContext>() -> Self {
        Interface {
            open: Some(open::<T>),
            get_security_by_name: Some(get_security_by_name::<T>),
            close: Some(close::<T>),
            create_ex: Some(create_ex::<T>),
            control: Some(control::<T>),
            overwrite_ex: Some(overwrite_ex::<T>),
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
            get_ea: Some(get_ea::<T>),
            set_ea: Some(set_ea::<T>),
            get_reparse_point: Some(get_reparse_point::<T>),
            set_reparse_point: Some(set_reparse_point::<T>),
            delete_reparse_point: Some(delete_reparse_point::<T>),
            resolve_reparse_points: Some(resolve_reparse_points::<T>),
            get_stream_info: Some(get_stream_info::<T>),
            get_dir_info_by_name: Some(get_dir_info_by_name::<T>),
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
            OverwriteEx: interface.overwrite_ex,
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
            GetEa: interface.get_ea,
            SetEa: interface.set_ea,
            GetReparsePoint: interface.get_reparse_point,
            SetReparsePoint: interface.set_reparse_point,
            DeleteReparsePoint: interface.delete_reparse_point,
            ResolveReparsePoints: interface.resolve_reparse_points,
            GetDirInfoByName: interface.get_dir_info_by_name,
            GetStreamInfo: interface.get_stream_info,
            ..Default::default()
        }
    }
}
