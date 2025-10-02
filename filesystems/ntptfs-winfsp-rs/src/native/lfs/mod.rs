pub(crate) mod async_io;

use std::ffi::c_void;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::ptr::{addr_of, addr_of_mut};
use std::slice;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_ALL_INFORMATION, FILE_ALLOCATION_INFORMATION, FILE_BASIC_INFORMATION,
    FILE_DISPOSITION_DELETE, FILE_DISPOSITION_DO_NOT_DELETE,
    FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX,
    FILE_DISPOSITION_INFORMATION_EX_FLAGS, FILE_DISPOSITION_POSIX_SEMANTICS,
    FILE_INFORMATION_CLASS, FILE_NAME_INFORMATION, FILE_STANDARD_INFORMATION, FileAllInformation,
    FileAllocationInformation, FileAttributeTagInformation, FileBasicInformation,
    FileDispositionInformation, FileDispositionInformationEx, FileEndOfFileInformation,
    FileFsSizeInformation, FileNameInformation, FileRenameInformation, FileRenameInformationEx,
    FileStandardInformation, FileStreamInformation, NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS, NtFsControlFile, NtQueryDirectoryFile, NtReadFile, NtWriteFile,
};
use windows::core::PCWSTR;

use windows::Wdk::Storage::FileSystem::{
    NtCreateFile, NtFlushBuffersFileEx, NtOpenFile, NtQueryInformationFile, NtQuerySecurityObject,
    NtQueryVolumeInformationFile, NtSetInformationFile, NtSetSecurityObject, ZwQueryEaFile,
    ZwSetEaFile,
};
use windows::Wdk::System::SystemServices::{
    FILE_ATTRIBUTE_TAG_INFORMATION, FILE_FS_SIZE_INFORMATION,
};
use windows::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, OBJECT_ATTRIBUTE_FLAGS, STATUS_ACCESS_DENIED,
    STATUS_BUFFER_OVERFLOW, STATUS_CANNOT_DELETE, STATUS_DIRECTORY_NOT_EMPTY, STATUS_FILE_DELETED,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION, STATUS_PENDING,
};
use windows::Win32::Foundation::{NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_END_OF_FILE_INFO, FILE_READ_ATTRIBUTES,
    FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};
use windows::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::Foundation::WAIT_FAILED;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, INVALID_FILE_ATTRIBUTES,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::WindowsProgramming::RtlInitUnicodeString;
use winfsp::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX;

use winfsp::filesystem::{FileInfo, OpenFileInfo};
use winfsp::util::{HandleInnerMut, NtSafeHandle, VariableSizedBox};
use winfsp::{FspError, U16CStr};

fn initialize_object_attributes(
    obj_name: &UNICODE_STRING,
    attributes: OBJECT_ATTRIBUTE_FLAGS,
    root_dir: Option<HANDLE>,
    security_descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_dir.unwrap_or_default(),
        ObjectName: obj_name as *const _,
        Attributes: attributes,
        SecurityDescriptor: security_descriptor.map_or_else(std::ptr::null_mut, |s| s.0 as _),
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}

pub(crate) fn new_event() -> windows::core::Result<HANDLE> {
    unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
}

thread_local! {
    static LFS_EVENT: HANDLE = new_event().unwrap();
}

pub fn lfs_create_file(
    root_handle: HANDLE,
    file_name: &U16CStr,
    desired_access: FILE_ACCESS_RIGHTS,
    security_descriptor: PSECURITY_DESCRIPTOR,
    allocation_size: Option<&mut i64>,
    file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    create_disposition: NTCREATEFILE_CREATE_DISPOSITION,
    create_options: NTCREATEFILE_CREATE_OPTIONS,
    ea_buffer: &Option<&[u8]>,
) -> winfsp::Result<NtSafeHandle> {
    let unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        // wrapping add to get rid of slash..
        RtlInitUnicodeString(
            unicode_filename.as_mut_ptr(),
            PCWSTR(if file_name.len() == 0 {
                file_name.as_ptr()
            } else {
                file_name.as_ptr().wrapping_add(1)
            }),
        );
        unicode_filename.assume_init()
    };

    let object_attrs = initialize_object_attributes(
        &unicode_filename,
        OBJECT_ATTRIBUTE_FLAGS::default(),
        Some(root_handle),
        Some(security_descriptor),
    );

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);
    let ea_buffer: Option<&[u8]> = ea_buffer.as_deref();

    unsafe {
        NtCreateFile(
            handle.handle_mut(),
            FILE_READ_ATTRIBUTES | desired_access,
            &object_attrs,
            iosb.as_mut_ptr(),
            allocation_size.map(|r| r as *const i64),
            file_attributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            create_options,
            ea_buffer.map(|b| b.as_ptr() as *const c_void),
            ea_buffer.map_or(0, |b| b.len() as u32),
        )
        .ok()?;
    }

    Ok(handle)
}

pub fn lfs_open_file(
    root_handle: HANDLE,
    file_name: &U16CStr,
    desired_access: FILE_ACCESS_RIGHTS,
    open_options: NTCREATEFILE_CREATE_OPTIONS,
) -> winfsp::Result<NtSafeHandle> {
    let unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        // wrapping add to get rid of leading slash..
        RtlInitUnicodeString(
            unicode_filename.as_mut_ptr(),
            PCWSTR(if file_name.len() == 0 {
                file_name.as_ptr()
            } else {
                file_name.as_ptr().wrapping_add(1)
            }),
        );
        unicode_filename.assume_init()
    };

    let object_attrs = initialize_object_attributes(
        &unicode_filename,
        OBJECT_ATTRIBUTE_FLAGS::default(),
        Some(root_handle),
        None,
    );

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);

    unsafe {
        NtOpenFile(
            handle.handle_mut(),
            (FILE_READ_ATTRIBUTES | desired_access | SYNCHRONIZE).0,
            &object_attrs,
            iosb.as_mut_ptr(),
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0,
            open_options.0,
        )
    }
    .ok()?;

    Ok(handle)
}

fn nt_check_pending(
    status: NTSTATUS,
    event: &HANDLE,
    iosb: &MaybeUninit<IO_STATUS_BLOCK>,
) -> winfsp::Result<NTSTATUS> {
    if status == STATUS_PENDING {
        let wait_result = unsafe { WaitForSingleObject(*event, INFINITE) };
        if wait_result == WAIT_FAILED {
            unsafe { GetLastError() }.ok()?;
        }
        let code = unsafe { addr_of!((*iosb.as_ptr()).Anonymous.Status).read() };
        Ok(code)
    } else {
        Ok(status)
    }
}

pub fn lfs_read_file(
    handle: HANDLE,
    buffer: &mut [u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
        let offset = offset as i64;

        let result = unsafe {
            NtReadFile(
                handle,
                Some(*event),
                None,
                None,
                iosb.as_mut_ptr() as *mut _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                Some(&offset),
                None,
            )
        };

        let result = nt_check_pending(result, event, &iosb)?;

        if result != STATUS_SUCCESS {
            return Err(FspError::from(result));
        }

        let iosb = unsafe { iosb.assume_init() };
        *bytes_transferred = iosb.Information as u32;

        Ok(())
    })
}

pub fn lfs_write_file(
    handle: HANDLE,
    buffer: &[u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
        let offset = offset as i64;

        let result = unsafe {
            NtWriteFile(
                handle,
                Some(*event),
                None,
                None,
                iosb.as_mut_ptr() as *mut _,
                buffer.as_ptr() as *const _,
                buffer.len() as u32,
                Some(&offset),
                None,
            )
        };

        let result = nt_check_pending(result, event, &iosb)?;

        if result != STATUS_SUCCESS {
            return Err(FspError::from(result));
        }

        let iosb = unsafe { iosb.assume_init() };
        *bytes_transferred = iosb.Information as u32;

        Ok(())
    })
}

pub fn lfs_get_file_attributes(handle: HANDLE) -> winfsp::Result<u32> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    let mut file_attr_info: MaybeUninit<FILE_ATTRIBUTE_TAG_INFORMATION> = MaybeUninit::zeroed();

    let file_attr_info = unsafe {
        NtQueryInformationFile(
            handle,
            iosb.as_mut_ptr(),
            file_attr_info.as_mut_ptr().cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
            FileAttributeTagInformation,
        )
        .ok()?;
        file_attr_info.assume_init()
    };

    Ok(file_attr_info.FileAttributes)
}

pub fn lfs_get_security(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: PSECURITY_DESCRIPTOR,
    security_descriptor_length: u32,
) -> winfsp::Result<u32> {
    let mut length_needed = 0;

    unsafe {
        NtQuerySecurityObject(
            handle,
            security_information,
            Some(security_descriptor),
            security_descriptor_length,
            &mut length_needed,
        )
        .ok()?;
    }

    Ok(length_needed)
}

#[inline(always)]
pub fn lfs_get_ea_size(ea_size: u32) -> u32 {
    if ea_size != 0 {
        ea_size.wrapping_sub(4)
    } else {
        0
    }
}

pub fn lfs_get_file_name(handle: HANDLE) -> winfsp::Result<Box<[u16]>> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    let mut name_info: VariableSizedBox<FILE_NAME_INFORMATION> = VariableSizedBox::new(
        winfsp::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX
            + offset_of!(FILE_NAME_INFORMATION, FileName),
    );

    unsafe {
        NtQueryInformationFile(
            handle,
            iosb.as_mut_ptr(),
            name_info.as_mut_ptr().cast(),
            name_info.len() as u32,
            FileNameInformation,
        )
        .ok()?;
    };

    let slice = unsafe {
        let slice = slice::from_raw_parts(
            name_info.as_ref().FileName.as_ptr(),
            (name_info.as_ref().FileNameLength as usize) / size_of::<u16>(),
        );
        slice.to_vec().into_boxed_slice()
    };

    Ok(slice)
}

// quick hack to be polymorphic for lfs_get_file_info
pub enum MaybeOpenFileInfo<'a> {
    FileInfo(&'a mut FileInfo),
    OpenFileInfo(&'a mut OpenFileInfo),
}

impl AsRef<FileInfo> for MaybeOpenFileInfo<'_> {
    fn as_ref(&self) -> &FileInfo {
        match self {
            MaybeOpenFileInfo::FileInfo(f) => f,
            MaybeOpenFileInfo::OpenFileInfo(f) => f.as_ref(),
        }
    }
}

impl AsMut<FileInfo> for MaybeOpenFileInfo<'_> {
    fn as_mut(&mut self) -> &mut FileInfo {
        match self {
            MaybeOpenFileInfo::FileInfo(f) => f,
            MaybeOpenFileInfo::OpenFileInfo(f) => f.as_mut(),
        }
    }
}

impl<'a> From<&'a mut FileInfo> for MaybeOpenFileInfo<'a> {
    fn from(f: &'a mut FileInfo) -> Self {
        MaybeOpenFileInfo::FileInfo(f)
    }
}

impl<'a> From<&'a mut OpenFileInfo> for MaybeOpenFileInfo<'a> {
    fn from(f: &'a mut OpenFileInfo) -> Self {
        MaybeOpenFileInfo::OpenFileInfo(f)
    }
}

pub fn lfs_get_file_info<'a, P: Into<MaybeOpenFileInfo<'a>>>(
    handle: HANDLE,
    root_prefix_length: Option<u32>,
    file_info: P,
) -> winfsp::Result<()> {
    let mut maybe_file_info: MaybeOpenFileInfo<'_> = file_info.into();

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    let mut file_all_info: VariableSizedBox<FILE_ALL_INFORMATION> = VariableSizedBox::new(
        winfsp::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX
            + offset_of!(FILE_ALL_INFORMATION, NameInformation.FileName),
    );

    let mut file_attr_info: FILE_ATTRIBUTE_TAG_INFORMATION = FILE_ATTRIBUTE_TAG_INFORMATION {
        FileAttributes: 0,
        ReparseTag: 0,
    };

    let result = unsafe {
        NtQueryInformationFile(
            handle,
            iosb.as_mut_ptr(),
            file_all_info.as_mut_ptr().cast(),
            file_all_info.len() as u32,
            FileAllInformation,
        )
    };

    if result.is_err() && result != STATUS_BUFFER_OVERFLOW {
        return Err(FspError::from(result));
    }

    let file_all_info = unsafe { file_all_info.as_ref() };

    let is_reparse_point =
        FILE_ATTRIBUTE_REPARSE_POINT.0 & file_all_info.BasicInformation.FileAttributes != 0;

    if is_reparse_point {
        unsafe {
            NtQueryInformationFile(
                handle,
                iosb.as_mut_ptr(),
                (&mut file_attr_info) as *mut _ as *mut c_void,
                size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
                FileAttributeTagInformation,
            )
            .ok()?;
        }
    }

    {
        let file_info = maybe_file_info.as_mut();
        file_info.file_attributes = file_all_info.BasicInformation.FileAttributes;
        file_info.reparse_tag = if is_reparse_point {
            file_attr_info.ReparseTag
        } else {
            0
        };
        file_info.allocation_size = file_all_info.StandardInformation.AllocationSize as u64;
        file_info.file_size = file_all_info.StandardInformation.EndOfFile as u64;
        file_info.creation_time = file_all_info.BasicInformation.CreationTime as u64;
        file_info.last_access_time = file_all_info.BasicInformation.LastAccessTime as u64;
        file_info.last_write_time = file_all_info.BasicInformation.LastWriteTime as u64;
        file_info.change_time = file_all_info.BasicInformation.ChangeTime as u64;
        file_info.index_number = file_all_info.InternalInformation.IndexNumber as u64;
        file_info.hard_links = 0;
        file_info.ea_size = lfs_get_ea_size(file_all_info.EaInformation.EaSize);
    }

    if result == STATUS_BUFFER_OVERFLOW {
        return Ok(());
    }

    if let (Some(root_prefix_length_bytes), MaybeOpenFileInfo::OpenFileInfo(open_file)) =
        (root_prefix_length, maybe_file_info)
        && root_prefix_length_bytes != u32::MAX
        && open_file.normalized_name_size()
            > (size_of::<u16>() as u32 + file_all_info.NameInformation.FileNameLength) as u16
        && root_prefix_length_bytes <= file_all_info.NameInformation.FileNameLength
    {
        // get the file_name without root prefix
        let file_name = unsafe {
            slice::from_raw_parts(
                file_all_info.NameInformation.FileName.as_ptr().cast::<u8>(),
                file_all_info.NameInformation.FileNameLength as usize,
            )
        };

        let file_name = &file_name[(root_prefix_length_bytes as usize)..];
        let file_name: &[u16] = bytemuck::cast_slice(file_name);
        open_file.set_normalized_name(file_name, Some(b'\\' as u16));
    }

    Ok(())
}

pub fn lfs_get_file_size(handle: HANDLE) -> winfsp::Result<u64> {
    let mut file_std_info: MaybeUninit<FILE_STANDARD_INFORMATION> = MaybeUninit::zeroed();
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();

    unsafe {
        NtQueryInformationFile(
            handle,
            iosb.as_mut_ptr(),
            file_std_info.as_mut_ptr().cast(),
            size_of::<FILE_STANDARD_INFORMATION>() as u32,
            FileStandardInformation,
        )
        .ok()?;
    }

    Ok(unsafe { file_std_info.assume_init().EndOfFile as u64 })
}

pub fn lfs_flush(handle: HANDLE) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    unsafe {
        NtFlushBuffersFileEx(handle, 0, std::ptr::null(), 0, iosb.as_mut_ptr()).ok()?;
    }
    Ok(())
}

pub fn lfs_set_delete(handle: HANDLE, delete: bool) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    let disp_info_ex = FILE_DISPOSITION_INFORMATION_EX {
        Flags: if delete {
            FILE_DISPOSITION_INFORMATION_EX_FLAGS(
                FILE_DISPOSITION_DELETE.0
                    | FILE_DISPOSITION_POSIX_SEMANTICS.0
                    | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.0
                    | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK.0,
            )
        } else {
            FILE_DISPOSITION_DO_NOT_DELETE
        },
    };

    let result = unsafe {
        NtSetInformationFile(
            handle,
            iosb.as_mut_ptr(),
            &disp_info_ex as *const _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };

    if result.is_ok() {
        return Ok(());
    }

    match result {
        code @ STATUS_ACCESS_DENIED
        | code @ STATUS_DIRECTORY_NOT_EMPTY
        | code @ STATUS_CANNOT_DELETE
        | code @ STATUS_FILE_DELETED => return Err(FspError::from(code)),
        _ => unsafe {
            let disp_info = FILE_DISPOSITION_INFORMATION {
                DeleteFile: delete.into(),
            };

            NtSetInformationFile(
                handle,
                iosb.as_mut_ptr(),
                &disp_info as *const _ as *const c_void,
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
            .ok()?;
        },
    };

    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub enum LfsRenameSemantics {
    DoNotReplace,
    NtReplaceSemantics,
    PosixReplaceSemantics,
}

pub fn lfs_rename(
    root_handle: *mut c_void,
    handle: HANDLE,
    new_file_name: &[u16],
    replace_if_exists: LfsRenameSemantics,
) -> winfsp::Result<()> {
    let root_handle = HANDLE(root_handle);
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    // length in bytes
    let file_path_len = std::mem::size_of_val(new_file_name);

    let mut rename_info: VariableSizedBox<FILE_RENAME_INFO> = VariableSizedBox::new(
        FSP_FSCTL_TRANSACT_PATH_SIZEMAX + offset_of!(FILE_RENAME_INFO, FileName),
    );

    if winfsp::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX < file_path_len {
        return Err(STATUS_INVALID_PARAMETER.into());
    }

    unsafe {
        addr_of_mut!((*rename_info.as_mut_ptr()).RootDirectory).write(root_handle);
        addr_of_mut!((*rename_info.as_mut_ptr()).FileNameLength).write(file_path_len as u32);
        addr_of_mut!((*rename_info.as_mut_ptr()).FileName)
            .copy_from(new_file_name.as_ptr().cast(), new_file_name.len());
        addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.Flags).write(
            if replace_if_exists == LfsRenameSemantics::PosixReplaceSemantics {
                1
            } else {
                0
            } | 0x42, /*POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE*/
        )
    }

    let result = unsafe {
        NtSetInformationFile(
            handle,
            iosb.as_mut_ptr() as *mut _,
            rename_info.as_mut_ptr().cast(),
            rename_info.len() as u32,
            FileRenameInformationEx,
        )
    };

    if result == STATUS_SUCCESS {
        return Ok(());
    }

    match result {
        STATUS_ACCESS_DENIED | STATUS_OBJECT_NAME_COLLISION
            if replace_if_exists == LfsRenameSemantics::NtReplaceSemantics =>
        {
            Err(FspError::from(STATUS_ACCESS_DENIED))
        }
        _ => unsafe {
            (&raw mut (*rename_info.as_mut_ptr()).Anonymous.Flags).write(0);
            (&raw mut (*rename_info.as_mut_ptr()).Anonymous.ReplaceIfExists).write(
                if replace_if_exists != LfsRenameSemantics::DoNotReplace {
                    true
                } else {
                    false
                },
            );

            Ok(NtSetInformationFile(
                handle,
                iosb.as_mut_ptr(),
                rename_info.as_mut_ptr().cast(),
                rename_info.len() as u32,
                FileRenameInformation,
            )
            .ok()?)
        },
    }
}

pub fn lfs_set_allocation_size(handle: HANDLE, new_size: u64) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();

    let info = FILE_ALLOCATION_INFORMATION {
        AllocationSize: new_size as i64,
    };

    unsafe {
        NtSetInformationFile(
            handle,
            iosb.as_mut_ptr(),
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_ALLOCATION_INFORMATION>() as u32,
            FileAllocationInformation,
        )
        .ok()?;
    }

    Ok(())
}

pub fn lfs_set_eof(handle: HANDLE, new_size: u64) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();

    let info = FILE_END_OF_FILE_INFO {
        EndOfFile: new_size as i64,
    };

    unsafe {
        NtSetInformationFile(
            handle,
            iosb.as_mut_ptr(),
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_END_OF_FILE_INFO>() as u32,
            FileEndOfFileInformation,
        )
        .ok()?;
    }

    Ok(())
}

pub fn lfs_set_basic_info(
    handle: HANDLE,
    file_attributes: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();

    let file_attributes = if file_attributes == INVALID_FILE_ATTRIBUTES {
        0
    } else if file_attributes == 0 {
        FILE_ATTRIBUTE_NORMAL.0
    } else {
        file_attributes
    };

    let basic_info = FILE_BASIC_INFORMATION {
        CreationTime: creation_time,
        LastAccessTime: last_access_time,
        LastWriteTime: last_write_time,
        ChangeTime: change_time,
        FileAttributes: file_attributes,
    };

    unsafe {
        NtSetInformationFile(
            handle,
            iosb.as_mut_ptr(),
            &basic_info as *const _ as *const c_void,
            std::mem::size_of::<FILE_BASIC_INFORMATION>() as u32,
            FileBasicInformation,
        )
        .ok()?;
    }

    Ok(())
}

pub fn lfs_query_directory_file(
    handle: HANDLE,
    buffer: &mut [u8],
    class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    file_name: &Option<PCWSTR>,
    restart_scan: bool,
) -> winfsp::Result<usize> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
        let unicode_filename = file_name.map(|f| unsafe {
            let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
            RtlInitUnicodeString(unicode_filename.as_mut_ptr(), f);
            unicode_filename.assume_init()
        });

        let unicode_filename = unicode_filename.as_ref();

        let result = unsafe {
            NtQueryDirectoryFile(
                handle,
                Some(*event),
                None,
                None,
                iosb.as_mut_ptr() as *mut _,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                class,
                return_single_entry,
                unicode_filename.map(|p| p as *const UNICODE_STRING as *const _),
                restart_scan,
            )
        };

        let result = nt_check_pending(result, event, &iosb)?;

        if result != STATUS_SUCCESS {
            return Err(FspError::from(result));
        }

        Ok(unsafe { iosb.assume_init().Information })
    })
}

pub fn lfs_set_security(
    handle: HANDLE,
    information: u32,
    security_descriptor: PSECURITY_DESCRIPTOR,
) -> winfsp::Result<()> {
    unsafe {
        NtSetSecurityObject(handle, information, security_descriptor).ok()?;
    }

    Ok(())
}

pub fn lfs_fs_control_file(
    handle: HANDLE,
    control_code: u32,
    input: Option<&[u8]>,
    output: Option<&mut [u8]>,
) -> winfsp::Result<usize> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
        let input_len = input.as_ref().map_or(0, |f| f.len()) as u32;
        let output_len = output.as_ref().map_or(0, |f| f.len() as u32);

        let result = unsafe {
            NtFsControlFile(
                handle,
                Some(*event),
                None,
                None,
                iosb.as_mut_ptr() as *mut _,
                control_code,
                input.map(|p| p.as_ptr() as *const c_void),
                input_len,
                output.map(|p| p.as_mut_ptr() as *mut c_void),
                output_len,
            )
        };

        let result = nt_check_pending(result, event, &iosb)?;
        if result == STATUS_BUFFER_OVERFLOW {
            return Err(FspError::from(STATUS_BUFFER_TOO_SMALL));
        }
        if result != STATUS_SUCCESS {
            return Err(FspError::from(result));
        }

        Ok(unsafe { iosb.assume_init().Information })
    })
}

#[derive(Debug, Eq, PartialEq)]
pub struct LfsVolumeInfo {
    pub total_size: u64,
    pub free_size: u64,
}

pub fn lfs_get_volume_info(root_handle: HANDLE) -> winfsp::Result<LfsVolumeInfo> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();
    let mut fsize_info: MaybeUninit<FILE_FS_SIZE_INFORMATION> = MaybeUninit::zeroed();

    let fsize_info = unsafe {
        NtQueryVolumeInformationFile(
            root_handle,
            iosb.as_mut_ptr(),
            fsize_info.as_mut_ptr().cast(),
            size_of::<FILE_FS_SIZE_INFORMATION>() as u32,
            FileFsSizeInformation,
        )
        .ok()?;

        fsize_info.assume_init()
    };

    let sector_size = fsize_info.BytesPerSector;
    let sectors_per_alloc_unit = fsize_info.SectorsPerAllocationUnit;
    let alloc_unit = sector_size * sectors_per_alloc_unit;

    Ok(LfsVolumeInfo {
        total_size: fsize_info.TotalAllocationUnits as u64 * alloc_unit as u64,
        free_size: fsize_info.AvailableAllocationUnits as u64 * alloc_unit as u64,
    })
}

pub fn lfs_get_ea(handle: HANDLE, buffer: &mut [u8]) -> usize {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::zeroed();

    let result = unsafe {
        ZwQueryEaFile(
            handle,
            iosb.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            false,
            None,
            0,
            None,
            true,
        )
    };

    if result.is_err() && result != STATUS_BUFFER_OVERFLOW {
        return 0;
    }

    let iosb = unsafe { iosb.assume_init() };
    iosb.Information
}

pub fn lfs_set_ea(handle: HANDLE, buffer: &[u8]) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    unsafe {
        ZwSetEaFile(
            handle,
            iosb.as_mut_ptr(),
            buffer.as_ptr().cast(),
            buffer.len() as u32,
        )
        .ok()?;
    }

    Ok(())
}

pub fn lfs_get_stream_info(handle: HANDLE, buffer: &mut [u8]) -> winfsp::Result<usize> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    let result = unsafe {
        NtQueryInformationFile(
            handle,
            iosb.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            FileStreamInformation,
        )
    };

    if result.is_err() && result != STATUS_BUFFER_OVERFLOW {
        return Err(FspError::from(result));
    }

    Ok(unsafe { iosb.assume_init().Information })
}
