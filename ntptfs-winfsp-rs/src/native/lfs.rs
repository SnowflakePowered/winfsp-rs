use ntapi::ntioapi::{
    FileAllInformation, FileAllocationInformation, FileAttributeTagInformation,
    FileBasicInformation, FileDispositionInformation, FileDispositionInformationEx,
    FileEndOfFileInformation, FileNameInformation, FileRenameInformation, FileRenameInformationEx,
    FileStandardInformation, FILE_ALLOCATION_INFORMATION, FILE_ALL_INFORMATION,
    FILE_ATTRIBUTE_TAG_INFORMATION, FILE_BASIC_INFORMATION, FILE_DISPOSITION_INFORMATION,
    FILE_END_OF_FILE_INFORMATION, FILE_NAME_INFORMATION, FILE_STANDARD_INFORMATION,
};
use ntapi::winapi::um::fileapi::INVALID_FILE_ATTRIBUTES;

use ntapi::winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, LARGE_INTEGER};
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::ops::DerefMut;
use std::ptr::addr_of_mut;
use std::slice;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_CANNOT_DELETE, STATUS_DATATYPE_MISALIGNMENT, STATUS_DIRECTORY_NOT_EMPTY,
    STATUS_FILE_DELETED, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION, STATUS_PENDING,
    STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::WindowsProgramming::INFINITE;

use windows_sys::Win32::Foundation::{BOOLEAN, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    NtCreateFile, FILE_ATTRIBUTE_REPARSE_POINT, FILE_RENAME_INFO,
};

use crate::native::nt;
use crate::native::nt::NtQueryInformationFile;
use windows_sys::Win32::System::WindowsProgramming::{
    NtOpenFile, RtlInitUnicodeString, FILE_DISPOSITION_INFO_EX, IO_STATUS_BLOCK, OBJECT_ATTRIBUTES,
};
use winfsp::filesystem::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_OPEN_FILE_INFO};
use winfsp::util::{NtSafeHandle, VariableSizedBox};

macro_rules! r_return {
    ($res:expr) => {
        r_return!($res, ())
    };
    ($res:expr, $val:expr) => {
        if $res.is_ok() {
            Ok($val)
        } else {
            Err($res.into())
        }
    };
}

#[inline(always)]
fn into_large_integer(n: u64) -> LARGE_INTEGER {
    unsafe {
        let mut integer: LARGE_INTEGER = std::mem::zeroed();
        *integer.QuadPart_mut() = n as i64;
        integer
    }
}

#[inline(always)]
const fn into_bit_boolean(b: bool) -> BOOLEAN {
    if b {
        1
    } else {
        0
    }
}

fn initialize_object_attributes(
    obj_name: &mut UNICODE_STRING,
    attributes: u32,
    root_dir: Option<HANDLE>,
    security_descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_dir.unwrap_or_default().0,
        ObjectName: obj_name,
        Attributes: attributes,
        SecurityDescriptor: security_descriptor.map_or_else(std::ptr::null_mut, |s| s.0),
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}

thread_local! {
    static LFS_EVENT: HANDLE = new_thread_event().unwrap();
}

fn new_thread_event() -> windows::core::Result<HANDLE> {
    unsafe { CreateEventW(std::ptr::null(), true, false, PCWSTR::null()) }
}

pub fn lfs_create_file<P: Into<PCWSTR>>(
    root_handle: HANDLE,
    file_name: P,
    desired_access: u32,
    security_descriptor: PSECURITY_DESCRIPTOR,
    allocation_size: Option<&mut i64>,
    file_attributes: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: &mut Option<&mut [u8]>,
) -> winfsp::Result<NtSafeHandle> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        // wrapping add to get rid of slash..
        RtlInitUnicodeString(
            unicode_filename.as_mut_ptr(),
            file_name.into().0.wrapping_add(1),
        );
        unicode_filename.assume_init()
    };

    let mut object_attrs = initialize_object_attributes(
        &mut unicode_filename,
        0,
        Some(root_handle),
        Some(security_descriptor),
    );

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);

    let result = if let Some(buffer) = ea_buffer.as_deref_mut() {
        // the lifetime of buffer has to last until after NtCreateFile.
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.deref_mut().0,
                FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
                create_disposition,
                create_options,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        })
    } else {
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.deref_mut().0,
                FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
                create_disposition,
                create_options,
                std::ptr::null_mut(),
                0,
            )
        })
    };

    r_return!(result, handle)
}

pub fn lfs_open_file<P: Into<PCWSTR>>(
    root_handle: HANDLE,
    file_name: P,
    desired_access: u32,
    open_options: u32,
) -> winfsp::Result<NtSafeHandle> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        // wrapping add to get rid of slash..
        RtlInitUnicodeString(
            unicode_filename.as_mut_ptr(),
            file_name.into().0.wrapping_add(1),
        );
        unicode_filename.assume_init()
    };

    let mut object_attrs =
        initialize_object_attributes(&mut unicode_filename, 0, Some(root_handle), None);

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);

    let result = NTSTATUS(unsafe {
        NtOpenFile(
            &mut handle.deref_mut().0,
            FILE_READ_ATTRIBUTES.0 | desired_access,
            &mut object_attrs,
            iosb.as_mut_ptr(),
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
            open_options,
        )
    });

    r_return!(result, handle)
}

pub fn lfs_read_file(handle: HANDLE, buffer: &mut [u8], offset: u64) -> winfsp::Result<u64> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let mut offset = offset;

        let mut result = unsafe {
            NTSTATUS(nt::NtReadFile(
                handle.0,
                event.0,
                None,
                std::ptr::null_mut(),
                iosb.as_mut_ptr(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut offset,
                std::ptr::null_mut(),
            ))
        };

        if result == STATUS_PENDING {
            unsafe {
                WaitForSingleObject(*event, INFINITE);
            }
            let iosb = unsafe { iosb.assume_init() };
            result = NTSTATUS(unsafe { iosb.Anonymous.Status })
        }

        let iosb = unsafe { iosb.assume_init() };
        r_return!(result, iosb.Information as u64)
    })
}

pub fn lfs_write_file(handle: HANDLE, buffer: &[u8], offset: u64) -> winfsp::Result<u64> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let mut offset = offset;

        let mut result = unsafe {
            NTSTATUS(nt::NtWriteFile(
                handle.0,
                event.0,
                None,
                std::ptr::null_mut(),
                iosb.as_mut_ptr(),
                buffer.as_ptr().cast_mut().cast(),
                buffer.len() as u32,
                &mut offset,
                std::ptr::null_mut(),
            ))
        };

        if result == STATUS_PENDING {
            unsafe {
                WaitForSingleObject(*event, INFINITE);
            }
            let iosb = unsafe { iosb.assume_init() };
            result = NTSTATUS(unsafe { iosb.Anonymous.Status })
        }

        let iosb = unsafe { iosb.assume_init() };
        r_return!(result, iosb.Information as u64)
    })
}

pub fn lfs_query_file_attributes(handle: HANDLE) -> winfsp::Result<u32> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut file_attr_info = FILE_ATTRIBUTE_TAG_INFORMATION {
        FileAttributes: 0,
        ReparseTag: 0,
    };

    let result = unsafe {
        NTSTATUS(nt::NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            &mut file_attr_info as *mut _ as *mut c_void,
            size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
            FileAttributeTagInformation as i32, /*FileAttributeTagInformation*/
        ))
    };

    r_return!(result, file_attr_info.FileAttributes)
}

pub fn lfs_query_security(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: PSECURITY_DESCRIPTOR,
    security_descriptor_length: u32,
) -> winfsp::Result<u32> {
    let mut length_needed = 0;
    let result = unsafe {
        NTSTATUS(nt::NtQuerySecurityObject(
            handle.0,
            security_information,
            security_descriptor.0,
            security_descriptor_length,
            &mut length_needed,
        ))
    };

    r_return!(result, length_needed)
}

#[inline(always)]
pub fn lfs_get_ea_size(ea_size: u32) -> u32 {
    if ea_size != 0 {
        ea_size.wrapping_sub(4)
    } else {
        0
    }
}

pub fn lfs_query_file_name(handle: HANDLE) -> winfsp::Result<Box<[u16]>> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut name_info: VariableSizedBox<FILE_NAME_INFORMATION> = VariableSizedBox::new(
        winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
            + size_of::<FILE_NAME_INFORMATION>()
            + 1,
    );

    let result = unsafe {
        NTSTATUS(nt::NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            name_info.as_mut_ptr().cast(),
            name_info.len() as u32,
            FileNameInformation as i32,
        ))
    };

    let slice = unsafe {
        let slice = slice::from_raw_parts(
            name_info.as_ref().FileName.as_ptr(),
            (name_info.as_ref().FileNameLength as usize) / size_of::<u16>(),
        );
        slice.to_vec().into_boxed_slice()
    };

    r_return!(result, slice)
}

pub fn lfs_get_file_info(
    handle: HANDLE,
    root_prefix_length: Option<u32>,
    file_info: &mut FSP_FSCTL_FILE_INFO,
) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut file_all_info: VariableSizedBox<FILE_ALL_INFORMATION> = VariableSizedBox::new(
        winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
            + size_of::<FILE_ALL_INFORMATION>()
            + 1,
    );
    let mut file_attr_info: FILE_ATTRIBUTE_TAG_INFORMATION = FILE_ATTRIBUTE_TAG_INFORMATION {
        FileAttributes: 0,
        ReparseTag: 0,
    };

    let result = unsafe {
        NTSTATUS(nt::NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            file_all_info.as_mut_ptr().cast(),
            file_all_info.len() as u32,
            FileAllInformation as i32,
        ))
    };

    if result.is_err() && result != STATUS_BUFFER_OVERFLOW {
        return Err(result.into());
    }

    let file_all_info = unsafe { file_all_info.as_ref() };

    let is_reparse_point =
        FILE_ATTRIBUTE_REPARSE_POINT & file_all_info.BasicInformation.FileAttributes != 0;

    if is_reparse_point {
        unsafe {
            let result = NTSTATUS(nt::NtQueryInformationFile(
                handle.0,
                iosb.as_mut_ptr(),
                (&mut file_attr_info) as *mut _ as *mut c_void,
                size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
                FileAttributeTagInformation as i32,
            ));

            if result != STATUS_SUCCESS {
                return Err(result.into());
            }
        }
    }

    file_info.FileAttributes = file_all_info.BasicInformation.FileAttributes;
    file_info.ReparseTag = if is_reparse_point {
        file_attr_info.ReparseTag
    } else {
        0
    };
    file_info.AllocationSize =
        unsafe { *(file_all_info.StandardInformation.AllocationSize.QuadPart()) as u64 };
    file_info.FileSize =
        unsafe { *(file_all_info.StandardInformation.EndOfFile.QuadPart()) as u64 };
    file_info.CreationTime =
        unsafe { *(file_all_info.BasicInformation.CreationTime.QuadPart()) as u64 };
    file_info.LastAccessTime =
        unsafe { *(file_all_info.BasicInformation.LastAccessTime.QuadPart()) as u64 };
    file_info.LastWriteTime =
        unsafe { *(file_all_info.BasicInformation.LastWriteTime.QuadPart()) as u64 };
    file_info.ChangeTime =
        unsafe { *(file_all_info.BasicInformation.ChangeTime.QuadPart()) as u64 };
    file_info.IndexNumber =
        unsafe { *(file_all_info.InternalInformation.IndexNumber.QuadPart()) as u64 };
    file_info.HardLinks = 0;
    file_info.EaSize = lfs_get_ea_size(file_all_info.EaInformation.EaSize);

    if let Some(root_prefix_length_bytes) = root_prefix_length && result != STATUS_BUFFER_OVERFLOW && root_prefix_length_bytes != u32::MAX {
        // SAFETY: if root_prefix_length_bytes is not a 1-bit pattern, then FILE_INFO is really an OPEN_FILE_INFO.
        // type pun takes ownership of mut reference so it is still exclusive.
        let open_file = unsafe { &mut *(file_info as *mut FSP_FSCTL_FILE_INFO as *mut FSP_FSCTL_OPEN_FILE_INFO) };

        if open_file.NormalizedNameSize > (size_of::<u16>() as u32 + file_all_info.NameInformation.FileNameLength as u32) as u16
            && root_prefix_length_bytes <= file_all_info.NameInformation.FileNameLength {
            let first_letter = file_all_info.NameInformation.FileName[0];

            // get the file_name without root prefix
            let file_name = unsafe {
                slice::from_raw_parts(file_all_info.NameInformation.FileName.as_ptr().cast::<u8>(),
                                      file_all_info.NameInformation.FileNameLength as usize)
            };

            let file_name = &file_name[(root_prefix_length_bytes as usize)..];

            if first_letter == b'\\' as u16 {
                unsafe {
                    open_file.NormalizedName.cast::<u8>().copy_from_nonoverlapping(file_name.as_ptr(), file_name.len());
                    open_file.NormalizedNameSize = file_name.len() as u16;
                }
            } else {
                unsafe {
                    open_file.NormalizedName.write(b'\\' as u16);
                    open_file.NormalizedName.wrapping_add(1).cast::<u8>().
                        copy_from_nonoverlapping(file_name.as_ptr(), file_name.len());
                    open_file.NormalizedNameSize = file_name.len() as u16 + size_of::<u16>() as u16;
                }
            }
        }
    }

    Ok(())
}

pub fn lfs_query_file_size(handle: HANDLE) -> winfsp::Result<u64> {
    let mut file_std_info: MaybeUninit<FILE_STANDARD_INFORMATION> = MaybeUninit::uninit();
    let result = unsafe {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        NTSTATUS(NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            file_std_info.as_mut_ptr().cast(),
            size_of::<FILE_STANDARD_INFORMATION>() as u32,
            FileStandardInformation as i32,
        ))
    };

    r_return!(
        result,
        unsafe { *file_std_info.assume_init().EndOfFile.QuadPart() } as u64
    )
}

pub fn lfs_flush(handle: HANDLE) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let result = unsafe { NTSTATUS(nt::NtFlushBuffersFile(handle.0, iosb.as_mut_ptr())) };
    r_return!(result)
}

// todo: make these return winfsp
pub fn lfs_set_delete(handle: HANDLE, delete: bool) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut disp_info = FILE_DISPOSITION_INFORMATION {
        DeleteFileA: into_bit_boolean(delete),
    };

    let mut disp_info_ex = FILE_DISPOSITION_INFO_EX {
        Flags: if delete {
            0x17 /*DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE | FORCE_IMAGE_SECTION_CHECK*/
        } else {
            0
        },
    };

    let result = unsafe {
        NTSTATUS(nt::NtSetInformationFileGeneric(
            handle.0,
            iosb.as_mut_ptr(),
            &mut disp_info_ex,
            FileDispositionInformationEx as i32, /*FileDispositionInformationEx*/
        ))
    };

    let result = match result {
        STATUS_ACCESS_DENIED
        | STATUS_DIRECTORY_NOT_EMPTY
        | STATUS_CANNOT_DELETE
        | STATUS_FILE_DELETED => result,
        _ => {
            unsafe {
                NTSTATUS(nt::NtSetInformationFileGeneric(
                    handle.0,
                    iosb.as_mut_ptr(),
                    &mut disp_info,
                    FileDispositionInformation as i32, /*FileDispositionInformation*/
                ))
            }
        }
    };

    r_return!(result)
}

#[derive(Eq, PartialEq)]
pub enum LfsRenameSemantics {
    DoNotReplace,
    NtReplaceSemantics,
    PosixReplaceSemantics,
}

pub fn lfs_rename(
    root_handle: HANDLE,
    handle: HANDLE,
    new_file_name: windows::core::HSTRING,
    replace_if_exists: LfsRenameSemantics,
) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    // todo: check if needs to be null_checked
    let file_path_len = (new_file_name.len()) * std::mem::size_of::<u16>();
    let mut rename_info: VariableSizedBox<FILE_RENAME_INFO> =
        VariableSizedBox::new(file_path_len + std::mem::size_of::<FILE_RENAME_INFO>() + 1);

    if winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX < file_path_len as u32 {
        return Err(STATUS_INVALID_PARAMETER.into());
    }

    unsafe {
        addr_of_mut!((*rename_info.as_mut_ptr()).RootDirectory).write(root_handle.0);
        addr_of_mut!((*rename_info.as_mut_ptr()).FileNameLength).write(file_path_len as u32);
        addr_of_mut!((*rename_info.as_mut_ptr()).FileName).copy_from(
            new_file_name.as_ptr().wrapping_add(1).cast(),
            new_file_name
                .len()
                .checked_sub(1)
                .expect("filename invalid"),
        );
        addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.Flags).write(
            if replace_if_exists == LfsRenameSemantics::PosixReplaceSemantics {
                1
            } else {
                0
            } | 0x42, /*POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE*/
        )
    }

    let result = unsafe {
        NTSTATUS(nt::NtSetInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            rename_info.as_mut_ptr().cast(),
            rename_info.len() as u32,
            FileRenameInformationEx as i32, /*FileRenameInformationEx*/
        ))
    };

    let result = match result {
        STATUS_OBJECT_NAME_COLLISION
            if replace_if_exists != LfsRenameSemantics::PosixReplaceSemantics =>
        {
            STATUS_ACCESS_DENIED
        }
        STATUS_ACCESS_DENIED => {
            eprintln!("access denied");
            STATUS_ACCESS_DENIED
        }
        _ => {
            unsafe {
                addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.Flags).write(0);
                addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.ReplaceIfExists).write(
                    if replace_if_exists != LfsRenameSemantics::DoNotReplace {
                        1
                    } else {
                        0
                    },
                );
                NTSTATUS(nt::NtSetInformationFile(
                    handle.0,
                    iosb.as_mut_ptr(),
                    rename_info.as_mut_ptr().cast(),
                    rename_info.len() as u32,
                    FileRenameInformation as i32, /*FileRenameInformation*/
                ))
            }
        }
    };

    r_return!(result)
}

pub fn lfs_set_allocation_size(handle: HANDLE, new_size: u64) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    let mut info = FILE_ALLOCATION_INFORMATION {
        AllocationSize: into_large_integer(new_size),
    };

    let result = NTSTATUS(unsafe {
        nt::NtSetInformationFileGeneric(
            handle.0,
            iosb.as_mut_ptr(),
            &mut info,
            FileAllocationInformation as i32,
        )
    });

    r_return!(result)
}

pub fn lfs_set_eof(handle: HANDLE, new_size: u64) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    let mut info = FILE_END_OF_FILE_INFORMATION {
        EndOfFile: into_large_integer(new_size),
    };

    let result = NTSTATUS(unsafe {
        nt::NtSetInformationFileGeneric(
            handle.0,
            iosb.as_mut_ptr(),
            &mut info,
            FileEndOfFileInformation as i32,
        )
    });
    r_return!(result)
}

pub fn lfs_set_basic_info(
    handle: HANDLE,
    file_attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
) -> winfsp::Result<()> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

    let file_attributes = if file_attributes == INVALID_FILE_ATTRIBUTES {
        0
    } else if file_attributes == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        file_attributes
    };

    let mut basic_info = FILE_BASIC_INFORMATION {
        CreationTime: into_large_integer(creation_time),
        LastAccessTime: into_large_integer(last_access_time),
        LastWriteTime: into_large_integer(last_write_time),
        ChangeTime: into_large_integer(change_time),
        FileAttributes: file_attributes,
    };

    let result = unsafe {
        NTSTATUS(nt::NtSetInformationFileGeneric(
            handle.0,
            iosb.as_mut_ptr(),
            &mut basic_info,
            FileBasicInformation as i32,
        ))
    };
    r_return!(result)
}

pub fn lfs_query_directory_file(
    handle: HANDLE,
    buffer: &mut [u8],
    class: i32,
    return_single_entry: bool,
    file_name: &Option<PCWSTR>,
    restart_scan: bool,
) -> winfsp::Result<usize> {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let unicode_filename = file_name.map(|f| unsafe {
            let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
            RtlInitUnicodeString(unicode_filename.as_mut_ptr(), f.0);
            unicode_filename.assume_init()
        });

        let mut result = unsafe {
            // lifetime of unicode_filename must be past the NtQueryDirectoryFile.
            if let Some(mut file_name) = unicode_filename {
                NTSTATUS(nt::NtQueryDirectoryFile(
                    handle.0,
                    event.0,
                    None,
                    std::ptr::null_mut(),
                    iosb.as_mut_ptr(),
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    class,
                    into_bit_boolean(return_single_entry),
                    &mut file_name,
                    into_bit_boolean(restart_scan),
                ))
            } else {
                NTSTATUS(nt::NtQueryDirectoryFile(
                    handle.0,
                    event.0,
                    None,
                    std::ptr::null_mut(),
                    iosb.as_mut_ptr(),
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    class,
                    into_bit_boolean(return_single_entry),
                    std::ptr::null_mut(),
                    into_bit_boolean(restart_scan),
                ))
            }
        };

        if result == STATUS_PENDING {
            unsafe {
                WaitForSingleObject(*event, INFINITE);
            }
            let iosb = unsafe { iosb.assume_init() };
            result = NTSTATUS(unsafe { iosb.Anonymous.Status });
        }

        r_return!(result, unsafe { iosb.assume_init().Information })
    })
}
