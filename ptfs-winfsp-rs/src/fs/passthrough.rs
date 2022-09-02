use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::ops::BitXor;

use std::os::windows::fs::MetadataExt;
use std::path::Path;
use widestring::{u16cstr, U16CStr, U16CString, U16String};

use windows::core::{HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{
    GetLastError, BOOLEAN, HANDLE, MAX_PATH, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_OBJECT_NAME_INVALID,
};
use windows::Win32::Security::{
    GetKernelObjectSecurity, SetKernelObjectSecurity, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAllocationInfo, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo,
    FileEndOfFileInfo, FindClose, FindFirstFileW, FindNextFileW, FlushFileBuffers,
    GetDiskFreeSpaceExW, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileSizeEx,
    GetFinalPathNameByHandleW, GetVolumePathNameW, MoveFileExW, ReadFile,
    SetFileInformationByHandle, WriteFile, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    FILE_ACCESS_FLAGS, FILE_ALLOCATION_INFO, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_END_OF_FILE_INFO,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE,
    FILE_FLAG_POSIX_SEMANTICS, FILE_NAME, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING,
    MOVE_FILE_FLAGS, OPEN_EXISTING, READ_CONTROL, WIN32_FIND_DATAW,
};
use windows::Win32::System::WindowsProgramming::{FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE};
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};

use winfsp::error::{FspError, Result};
use winfsp::filesystem::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirBuffer, DirInfo, FileSecurity, FileSystemContext, FileSystemHost, IoResult,
    FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};

use winfsp::util::SafeDropHandle;

const ALLOCATION_UNIT: u16 = 4096;
const VOLUME_LABEL: &HSTRING = w!("Snowflake");
const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
        / std::mem::size_of::<u16>());

pub struct Ptfs {
    pub fs: FileSystemHost,
}

#[repr(C)]
pub struct PtfsContext {
    path: OsString,
}

#[repr(C)]
pub struct PtfsFileContext {
    handle: SafeDropHandle,
    dir_buffer: DirBuffer,
}

#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

macro_rules! win32_try {
    (unsafe $e:expr) => {
        if unsafe { !($e).as_bool() } {
            return Err(::winfsp::error::FspError::from(unsafe { GetLastError() }));
        }
    };
}

impl PtfsContext {
    fn get_file_info_internal(
        &self,
        file_handle: HANDLE,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        win32_try!(unsafe GetFileInformationByHandle(file_handle, &mut os_file_info));

        file_info.FileAttributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = quadpart(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
        file_info.CreationTime = quadpart(
            os_file_info.ftCreationTime.dwHighDateTime,
            os_file_info.ftCreationTime.dwLowDateTime,
        );
        file_info.LastAccessTime = quadpart(
            os_file_info.ftLastAccessTime.dwHighDateTime,
            os_file_info.ftLastAccessTime.dwLowDateTime,
        );
        file_info.LastWriteTime = quadpart(
            os_file_info.ftLastWriteTime.dwHighDateTime,
            os_file_info.ftLastWriteTime.dwLowDateTime,
        );
        file_info.ChangeTime = file_info.LastWriteTime;
        Ok(())
    }
}

impl FileSystemContext for PtfsContext {
    type FileContext = PtfsFileContext;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        security_descriptor_len: Option<u64>,
    ) -> Result<FileSecurity> {
        // return Err(STATUS_INVALID_DEVICE_REQUEST.into());
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));

        let handle = unsafe {
            let handle = CreateFileW(
                &HSTRING::from(full_path.as_os_str()),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_MODE(0),
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )?;
            if handle.is_invalid() {
                return Err(FspError::from(GetLastError()));
            }
            handle
        };

        let mut attribute_tag_info: MaybeUninit<FILE_ATTRIBUTE_TAG_INFO> = MaybeUninit::uninit();
        let mut len_needed: u32 = 0;

        let handle = SafeDropHandle::from(handle);

        win32_try!(unsafe GetFileInformationByHandleEx(
            *handle,
            FileAttributeTagInfo,
            attribute_tag_info.as_mut_ptr() as *mut _,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        ));

        if let Some(descriptor_len) = security_descriptor_len {
            win32_try!(unsafe GetKernelObjectSecurity(
                *handle,
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len as u32,
                &mut len_needed,
            ));
        }

        Ok(FileSecurity {
            attributes: unsafe { attribute_tag_info.assume_init() }.FileAttributes,
            reparse: false,
            sz_security_descriptor: len_needed as u64,
        })
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
        if full_path.len() > FULLPATH_SIZE {
            return Err(STATUS_OBJECT_NAME_INVALID.into());
        }

        let full_path = U16CString::from_os_str_truncate(full_path);
        let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
            create_flags |= FILE_FLAG_DELETE_ON_CLOSE
        }

        let handle = unsafe {
            let handle = CreateFileW(
                PCWSTR(full_path.as_ptr()),
                granted_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                create_flags,
                None,
            )?;
            if handle.is_invalid() {
                return Err(FspError::from(GetLastError()));
            }
            handle
        };

        if handle.is_invalid() {
            return Err(unsafe { GetLastError().into() });
        }

        self.get_file_info_internal(handle, file_info)?;
        Ok(Self::FileContext {
            handle: SafeDropHandle::from(handle),
            dir_buffer: DirBuffer::new(),
        })
    }

    fn close(&self, context: Self::FileContext) {
        drop(context)
    }

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> Result<()> {
        let mut root = [0u16; MAX_PATH as usize];
        let mut total_size = 0u64;
        let mut free_size = 0u64;
        let fname = U16CString::from_os_str_truncate(self.path.as_os_str());
        win32_try!(unsafe GetVolumePathNameW(PCWSTR(fname.as_ptr()), &mut root[..]));
        win32_try!(unsafe GetDiskFreeSpaceExW(
            PCWSTR(U16CStr::from_slice_truncate(&root).unwrap().as_ptr()),
            std::ptr::null_mut(),
            &mut total_size,
            &mut free_size,
        ));

        out_volume_info.TotalSize = total_size;
        out_volume_info.FreeSize = free_size;
        out_volume_info.VolumeLabel[0..VOLUME_LABEL.len()].copy_from_slice(VOLUME_LABEL.as_wide());
        out_volume_info.VolumeLabelLength =
            (VOLUME_LABEL.len() * std::mem::size_of::<u16>()) as u16;
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        self.get_file_info_internal(*context.handle, file_info)
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<u64> {
        let mut descriptor_size_needed = 0;

        win32_try!(unsafe GetKernelObjectSecurity(
            *context.handle,
            (OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION)
                .0,
            security_descriptor,
            descriptor_len.unwrap_or(0) as u32,
            &mut descriptor_size_needed,
        ));

        Ok(descriptor_size_needed as u64)
    }

    fn read_directory<P: Into<PCWSTR>>(
        &self,
        context: &mut Self::FileContext,
        pattern: Option<P>,
        marker: Option<&[u16]>,
        buffer: &mut [u8],
    ) -> Result<u32> {
        if let Ok(mut lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();
            let mut full_path = [0; FULLPATH_SIZE];

            let pattern = pattern.map_or(PCWSTR::from(w!("*")), P::into);
            let pattern = unsafe { U16CStr::from_ptr_str(pattern.0) };

            let mut length = unsafe {
                GetFinalPathNameByHandleW(
                    *context.handle,
                    &mut full_path[0..FULLPATH_SIZE - 1],
                    FILE_NAME::default(),
                )
            };

            if length == 0 {
                return Err(unsafe { GetLastError() }.into());
            } else if length as usize + 1 + pattern.len() >= FULLPATH_SIZE {
                return Err(STATUS_OBJECT_NAME_INVALID.into());
            }

            // append '\'
            if full_path[length as usize - 1] != '\\' as u16 {
                full_path[length as usize..][0..2]
                    .copy_from_slice(u16cstr!("\\").as_slice_with_nul());
                length += 1;
            }

            let mut full_path =
                unsafe { U16String::from_ptr(&full_path as *const u16, length as usize) };

            full_path.push(pattern);

            let mut find_data = MaybeUninit::<WIN32_FIND_DATAW>::uninit();
            let full_path = U16CString::from_ustr_truncate(full_path);
            if let Ok(find_handle) = unsafe { FindFirstFileW(PCWSTR::from_raw(full_path.as_ptr()), find_data.as_mut_ptr()) } && !find_handle.is_invalid() {
                let mut find_data = unsafe { find_data.assume_init() };
                loop {
                    dirinfo.reset();
                    let finfo = dirinfo.file_info_mut();
                    finfo.FileAttributes = find_data.dwFileAttributes;
                    finfo.ReparseTag = 0;
                    finfo.FileSize = quadpart(find_data.nFileSizeHigh, find_data.nFileSizeLow);
                    finfo.AllocationSize = ((finfo.FileSize + ALLOCATION_UNIT as u64 - 1) / ALLOCATION_UNIT as u64) * ALLOCATION_UNIT as u64;
                    finfo.CreationTime = quadpart(find_data.ftCreationTime.dwHighDateTime, find_data.ftCreationTime.dwLowDateTime);
                    finfo.LastAccessTime = quadpart(find_data.ftLastAccessTime.dwHighDateTime, find_data.ftLastAccessTime.dwLowDateTime);
                    finfo.LastWriteTime = quadpart(find_data.ftLastWriteTime.dwHighDateTime, find_data.ftLastWriteTime.dwLowDateTime);
                    finfo.ChangeTime = finfo.LastWriteTime;
                    finfo.HardLinks = 0;
                    finfo.IndexNumber = 0;

                    dirinfo.set_file_name(&find_data.cFileName[..])?;
                    if let Err(e) = lock.fill(&mut dirinfo) {
                        unsafe {
                            FindClose(find_handle);
                        }
                        drop(lock);
                        return Err(e);
                    }
                    if unsafe {
                        !FindNextFileW(HANDLE(find_handle.0), &mut find_data).as_bool()
                    } {
                        break;
                    }
                }
                unsafe {
                    FindClose(find_handle);
                }
                drop(lock);
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<IoResult> {
        let mut overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: offset as u32,
                    OffsetHigh: (offset >> 32) as u32,
                },
            },
            ..Default::default()
        };

        let mut bytes_read = 0;
        win32_try!(unsafe ReadFile(
            *context.handle,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            &mut overlapped,
        ));

        Ok(IoResult {
            bytes_transferred: bytes_read,
            io_pending: false,
        })
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<IoResult> {
        if constrained_io {
            let mut fsize = 0;
            win32_try!(unsafe GetFileSizeEx(*context.handle, &mut fsize));

            if offset >= fsize as u64 {
                return Ok(IoResult {
                    bytes_transferred: 0,
                    io_pending: false,
                });
            }

            if offset + buffer.len() as u64 > fsize as u64 {
                buffer = &buffer[0..(fsize as u64 - offset) as usize]
            }
        }

        let mut overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: offset as u32,
                    OffsetHigh: (offset >> 32) as u32,
                },
            },
            ..Default::default()
        };

        let mut bytes_transferred = 0;
        win32_try!(unsafe WriteFile(
            *context.handle,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_transferred,
            &mut overlapped,
        ));

        self.get_file_info_internal(*context.handle, file_info)?;
        Ok(IoResult {
            bytes_transferred,
            io_pending: false,
        })
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        _allocation_size: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        // todo: preserve allocation size
        let mut attribute_tag_info = FILE_ATTRIBUTE_TAG_INFO::default();

        if replace_file_attributes {
            let basic_info = FILE_BASIC_INFO {
                FileAttributes: if file_attributes == FILE_FLAGS_AND_ATTRIBUTES(0) {
                    FILE_ATTRIBUTE_NORMAL
                } else {
                    file_attributes
                }
                .0,
                ..Default::default()
            };

            win32_try!(unsafe SetFileInformationByHandle(
                *context.handle,
                FileBasicInfo,
                (&basic_info as *const FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            ));
        } else if file_attributes != FILE_FLAGS_AND_ATTRIBUTES(0) {
            let mut basic_info = FILE_BASIC_INFO::default();
            win32_try!(unsafe GetFileInformationByHandleEx(
                *context.handle,
                FileAttributeTagInfo,
                (&mut attribute_tag_info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ));

            basic_info.FileAttributes = file_attributes.0 | attribute_tag_info.FileAttributes;
            if basic_info.FileAttributes.bitxor(file_attributes.0) != 0 {
                win32_try!(unsafe SetFileInformationByHandle(
                    *context.handle,
                    FileBasicInfo,
                    (&basic_info as *const FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                ));
            }
        }

        let alloc_info = FILE_ALLOCATION_INFO::default();
        win32_try!(unsafe SetFileInformationByHandle(
            *context.handle,
            FileAllocationInfo,
            (&alloc_info as *const FILE_ALLOCATION_INFO).cast(),
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        ));
        self.get_file_info_internal(*context.handle, file_info)
    }

    fn create<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        mut file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
        if full_path.len() > FULLPATH_SIZE {
            return Err(STATUS_OBJECT_NAME_INVALID.into());
        }
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.0,
            bInheritHandle: false.into(),
        };

        let full_path = U16CString::from_os_str_truncate(full_path);
        let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
            create_flags |= FILE_FLAG_DELETE_ON_CLOSE;
        }

        if (create_options & FILE_DIRECTORY_FILE) != 0 {
            create_flags |= FILE_FLAG_POSIX_SEMANTICS;
            file_attributes |= FILE_ATTRIBUTE_DIRECTORY
        } else {
            file_attributes &= !FILE_ATTRIBUTE_DIRECTORY
        }

        if file_attributes == FILE_FLAGS_AND_ATTRIBUTES(0) {
            file_attributes = FILE_ATTRIBUTE_NORMAL
        }

        let handle = unsafe {
            let handle = CreateFileW(
                PCWSTR(full_path.as_ptr()),
                granted_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &security_attributes,
                CREATE_NEW,
                create_flags | file_attributes,
                None,
            )?;
            if handle.is_invalid() {
                return Err(FspError::from(GetLastError()));
            }
            handle
        };

        self.get_file_info_internal(handle, file_info)?;

        Ok(Self::FileContext {
            handle: SafeDropHandle::from(handle),
            dir_buffer: Default::default(),
        })
    }

    fn cleanup<P: AsRef<OsStr>>(
        &self,
        context: &mut Self::FileContext,
        _file_name: Option<P>,
        flags: u32,
    ) {
        if flags & FspCleanupFlags::FspCleanupDelete as u32 != 0 {
            context.handle.invalidate();
        }
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        let basic_info = FILE_BASIC_INFO {
            FileAttributes: if file_attributes == INVALID_FILE_ATTRIBUTES {
                0
            } else if file_attributes == 0 {
                FILE_ATTRIBUTE_NORMAL.0
            } else {
                file_attributes
            },
            CreationTime: creation_time as i64,
            LastAccessTime: last_access_time as i64,
            LastWriteTime: last_write_time as i64,
            ChangeTime: last_change_time as i64,
        };
        win32_try!(unsafe SetFileInformationByHandle(
            *context.handle,
            FileBasicInfo,
            (&basic_info as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        ));

        self.get_file_info_internal(*context.handle, file_info)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        if set_allocation_size {
            let allocation_info = FILE_ALLOCATION_INFO {
                AllocationSize: new_size as i64,
            };

            win32_try!(unsafe SetFileInformationByHandle(
                *context.handle,
                FileAllocationInfo,
                (&allocation_info as *const FILE_ALLOCATION_INFO).cast(),
                std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32
            ))
        } else {
            let eof_info = FILE_END_OF_FILE_INFO {
                EndOfFile: new_size as i64,
            };

            win32_try!(unsafe SetFileInformationByHandle(
                *context.handle,
                FileEndOfFileInfo,
                (&eof_info as *const FILE_END_OF_FILE_INFO).cast(),
                std::mem::size_of::<FILE_END_OF_FILE_INFO>() as u32
            ))
        }
        self.get_file_info_internal(*context.handle, file_info)
    }

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<()> {
        win32_try!(unsafe SetKernelObjectSecurity(
            *context.handle,
            security_information,
            modification_descriptor
        ));
        Ok(())
    }
    fn set_delete<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        delete_file: bool,
    ) -> Result<()> {
        let disposition_info = FILE_DISPOSITION_INFO {
            DeleteFileA: BOOLEAN(if delete_file { 1 } else { 0 }),
        };

        win32_try!(unsafe SetFileInformationByHandle(*context.handle,
            FileDispositionInfo, (&disposition_info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32));
        Ok(())
    }

    fn flush(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        if *context.handle == HANDLE(0) {
            // we do not flush the whole volume, so just return ok
            return Ok(());
        }

        win32_try!(unsafe FlushFileBuffers(*context.handle));
        self.get_file_info_internal(*context.handle, file_info)
    }

    fn rename<P: AsRef<OsStr>>(
        &self,
        _context: &Self::FileContext,
        file_name: P,
        new_file_name: P,
        replace_if_exists: bool,
    ) -> Result<()> {
        let full_path = {
            let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
            if full_path.len() > FULLPATH_SIZE {
                return Err(STATUS_OBJECT_NAME_INVALID.into());
            }
            U16CString::from_os_str_truncate(full_path)
        };

        let new_full_path = {
            let new_full_path =
                [self.path.as_os_str(), new_file_name.as_ref()].join(OsStr::new(""));
            if new_full_path.len() > FULLPATH_SIZE {
                return Err(STATUS_OBJECT_NAME_INVALID.into());
            }
            U16CString::from_os_str_truncate(new_full_path)
        };

        win32_try!(unsafe MoveFileExW(
            PCWSTR::from_raw(full_path.as_ptr()),
            PCWSTR::from_raw(new_full_path.as_ptr()),
            if replace_if_exists {
                MOVEFILE_REPLACE_EXISTING
            } else {
                MOVE_FILE_FLAGS::default()
            }
        ));

        Ok(())
    }
}

impl Ptfs {
    pub fn create<P: AsRef<Path>>(path: P, volume_prefix: &str) -> anyhow::Result<Ptfs> {
        let metadata = fs::metadata(&path)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(ErrorKind::NotADirectory, "not a directory").into());
        }

        let canonical_path = fs::canonicalize(&path)?;
        let mut volume_params = FSP_FSCTL_VOLUME_PARAMS {
            SectorSize: ALLOCATION_UNIT,
            SectorsPerAllocationUnit: 1,
            VolumeCreationTime: metadata.creation_time(),
            VolumeSerialNumber: 0,
            FileInfoTimeout: 1000,
            ..Default::default()
        };
        volume_params.set_CaseSensitiveSearch(0);
        volume_params.set_CasePreservedNames(1);
        volume_params.set_UnicodeOnDisk(1);
        volume_params.set_PersistentAcls(1);
        volume_params.set_PostCleanupWhenModifiedOnly(1);
        volume_params.set_PassQueryDirectoryPattern(1);
        volume_params.set_FlushAndPurgeOnCleanup(1);
        volume_params.set_UmFileContextIsUserContext2(1);

        let prefix = HSTRING::from(volume_prefix);
        let fs_name = w!("ptfs-winfsp-rs");

        volume_params.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix.as_wide()[..std::cmp::min(prefix.len(), 192)]);

        volume_params.FileSystemName[..std::cmp::min(fs_name.len(), 192)]
            .copy_from_slice(&fs_name.as_wide()[..std::cmp::min(fs_name.len(), 192)]);

        dbg!(HSTRING::from_wide(&volume_params.FileSystemName), fs_name);
        dbg!(HSTRING::from_wide(&volume_params.Prefix), prefix);

        let context = PtfsContext {
            path: canonical_path.into_os_string(),
        };

        unsafe {
            Ok(Ptfs {
                fs: FileSystemHost::new(volume_params, context)?,
            })
        }
    }
}
