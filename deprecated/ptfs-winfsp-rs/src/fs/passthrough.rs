use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::ops::BitXor;
use std::os::windows::ffi::OsStringExt;

use std::os::windows::fs::MetadataExt;
use std::path::Path;
use widestring::{u16cstr, U16CStr, U16CString, U16String};

use windows::core::{HSTRING, PCWSTR, w};
use windows::Wdk::Storage::FileSystem::{FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE};
use windows::Win32::Foundation::{
    GetLastError, BOOLEAN, HANDLE, MAX_PATH, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_INVALID,
};
use windows::Win32::Security::{
    GetKernelObjectSecurity, SetKernelObjectSecurity, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, FileAllocationInfo, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo, FileEndOfFileInfo, FindClose, FindFirstFileW, FindNextFileW, FlushFileBuffers, GetDiskFreeSpaceExW, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileSizeEx, GetFinalPathNameByHandleW, GetVolumePathNameW, MoveFileExW, ReadFile, SetFileInformationByHandle, WriteFile, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ACCESS_RIGHTS, FILE_ALLOCATION_INFO, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_END_OF_FILE_INFO, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_POSIX_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVE_FILE_FLAGS, OPEN_EXISTING, READ_CONTROL, WIN32_FIND_DATAW, FILE_NAME_NORMALIZED};
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};
use windows_sys::Win32::Storage::FileSystem::FILE_NAME;

use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileContextMode, FileSystemHost, VolumeParams};
use winfsp::{FspError, Result};

use winfsp::util::Win32SafeHandle;

const ALLOCATION_UNIT: u16 = 4096;
const VOLUME_LABEL: &str = "Snowflake";
const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX / std::mem::size_of::<u16>());

pub struct Ptfs {
    pub fs: FileSystemHost<PtfsContext>,
}

#[repr(C)]
pub struct PtfsContext {
    path: OsString,
}

#[repr(C)]
pub struct PtfsFileContext {
    handle: RefCell<Win32SafeHandle>,
    dir_buffer: DirBuffer,
}

impl PtfsFileContext {
    pub fn handle(&self) -> HANDLE {
        **self.handle.borrow()
    }

    pub fn invalidate(&self) {
        self.handle.borrow_mut().invalidate()
    }
}
#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

macro_rules! win32_try {
    (unsafe $e:expr) => {
        $e?
    };
}

impl PtfsContext {
    fn get_file_info_internal(&self, file_handle: HANDLE, file_info: &mut FileInfo) -> Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        win32_try!(unsafe GetFileInformationByHandle(file_handle, &mut os_file_info));

        file_info.file_attributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.reparse_tag = 0;
        file_info.index_number = 0;
        file_info.hard_links = 0;

        file_info.file_size = quadpart(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.allocation_size = (file_info.file_size + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
        file_info.creation_time = quadpart(
            os_file_info.ftCreationTime.dwHighDateTime,
            os_file_info.ftCreationTime.dwLowDateTime,
        );
        file_info.last_access_time = quadpart(
            os_file_info.ftLastAccessTime.dwHighDateTime,
            os_file_info.ftLastAccessTime.dwLowDateTime,
        );
        file_info.last_write_time = quadpart(
            os_file_info.ftLastWriteTime.dwHighDateTime,
            os_file_info.ftLastWriteTime.dwLowDateTime,
        );
        file_info.change_time = file_info.last_write_time;
        Ok(())
    }
}

impl FileSystemContext for PtfsContext {
    type FileContext = PtfsFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity> {
        let file_name = OsString::from_wide(file_name.as_slice());
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));

        let handle = unsafe {
            let handle = CreateFileW(
                &HSTRING::from(full_path.as_os_str()),
                (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
                FILE_SHARE_MODE(0),
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

        let mut attribute_tag_info: MaybeUninit<FILE_ATTRIBUTE_TAG_INFO> = MaybeUninit::uninit();
        let mut len_needed: u32 = 0;

        let handle = RefCell::new(Win32SafeHandle::from(handle));

        win32_try!(unsafe GetFileInformationByHandleEx(
            **handle.borrow(),
            FileAttributeTagInfo,
            attribute_tag_info.as_mut_ptr() as *mut _,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        ));

        if let Some(descriptor_len) = descriptor_len {
            win32_try!(unsafe GetKernelObjectSecurity(
                 **handle.borrow(),
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

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        let file_name = OsString::from_wide(file_name.as_slice());
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
                granted_access.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
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

        self.get_file_info_internal(handle, file_info.as_mut())?;
        Ok(Self::FileContext {
            handle: RefCell::new(Win32SafeHandle::from(handle)),
            dir_buffer: DirBuffer::new(),
        })
    }

    fn close(&self, context: Self::FileContext) {
        drop(context)
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        mut file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        let file_name = OsString::from_wide(file_name.as_slice());

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
                granted_access.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&security_attributes),
                CREATE_NEW,
                create_flags | file_attributes,
                None,
            )?;
            if handle.is_invalid() {
                return Err(FspError::from(GetLastError()));
            }
            handle
        };

        self.get_file_info_internal(handle, file_info.as_mut())?;

        Ok(Self::FileContext {
            handle: RefCell::new(Win32SafeHandle::from(handle)),
            dir_buffer: Default::default(),
        })
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        if flags & FspCleanupFlags::FspCleanupDelete as u32 != 0 {
            context.invalidate();
        }
    }

    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        if context.is_none() {
            return Ok(());
        }

        let context = context.unwrap();
        if context.handle() == HANDLE(0) {
            // we do not flush the whole volume, so just return ok
            return Ok(());
        }

        win32_try!(unsafe FlushFileBuffers(context.handle()));
        self.get_file_info_internal(context.handle(), file_info)
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        self.get_file_info_internal(context.handle(), file_info)
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<u64> {
        let mut descriptor_size_needed = 0;

        win32_try!(unsafe GetKernelObjectSecurity(
            context.handle(),
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

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<()> {
        win32_try!(unsafe SetKernelObjectSecurity(
            context.handle(),
            security_information,
            modification_descriptor
        ));
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
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
                context.handle(),
                FileBasicInfo,
                (&basic_info as *const FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            ));
        } else if file_attributes != FILE_FLAGS_AND_ATTRIBUTES(0) {
            let mut basic_info = FILE_BASIC_INFO::default();
            win32_try!(unsafe GetFileInformationByHandleEx(
                context.handle(),
                FileAttributeTagInfo,
                (&mut attribute_tag_info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ));

            basic_info.FileAttributes = file_attributes.0 | attribute_tag_info.FileAttributes;
            if basic_info.FileAttributes.bitxor(file_attributes.0) != 0 {
                win32_try!(unsafe SetFileInformationByHandle(
                    context.handle(),
                    FileBasicInfo,
                    (&basic_info as *const FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                ));
            }
        }

        let alloc_info = FILE_ALLOCATION_INFO::default();
        win32_try!(unsafe SetFileInformationByHandle(
            context.handle(),
            FileAllocationInfo,
            (&alloc_info as *const FILE_ALLOCATION_INFO).cast(),
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        ));
        self.get_file_info_internal(context.handle(), file_info)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
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
            context.handle(),
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read),
            Some(&mut overlapped),
        ));

        Ok(bytes_read)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();
            let pattern = pattern.map_or(PCWSTR::from(w!("*")), |p| PCWSTR(p.as_ptr()));
            let pattern = unsafe { U16CStr::from_ptr_str(pattern.0) };

            let mut full_path = [0; FULLPATH_SIZE];
            let mut length = unsafe {
                GetFinalPathNameByHandleW(
                    context.handle(),
                    &mut full_path[0..FULLPATH_SIZE - 1],
                    FILE_NAME_NORMALIZED,
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
            let full_path = U16CString::from_ustr_truncate(&full_path);
            if let Ok(find_handle) = unsafe { FindFirstFileW(PCWSTR::from_raw(full_path.as_ptr()), find_data.as_mut_ptr()) } && !find_handle.is_invalid() {
                let mut find_data = unsafe { find_data.assume_init() };
                loop {
                    dirinfo.reset();
                    let finfo = dirinfo.file_info_mut();
                    finfo.file_attributes = find_data.dwFileAttributes;
                    finfo.reparse_tag = 0;
                    finfo.file_size = quadpart(find_data.nFileSizeHigh, find_data.nFileSizeLow);
                    finfo.allocation_size = ((finfo.file_size + ALLOCATION_UNIT as u64 - 1) / ALLOCATION_UNIT as u64) * ALLOCATION_UNIT as u64;
                    finfo.creation_time = quadpart(find_data.ftCreationTime.dwHighDateTime, find_data.ftCreationTime.dwLowDateTime);
                    finfo.last_access_time = quadpart(find_data.ftLastAccessTime.dwHighDateTime, find_data.ftLastAccessTime.dwLowDateTime);
                    finfo.last_write_time = quadpart(find_data.ftLastWriteTime.dwHighDateTime, find_data.ftLastWriteTime.dwLowDateTime);
                    finfo.change_time = finfo.last_write_time;
                    finfo.hard_links = 0;
                    finfo.index_number = 0;

                    // find null ptr
                    let file_name =
                        U16CStr::from_slice_truncate(&find_data.cFileName[..]).map_err(|_| STATUS_INVALID_PARAMETER)?;
                    let file_name = file_name.as_slice();

                    dirinfo.set_name_raw(file_name)?;

                    if let Err(e) = lock.write(&mut dirinfo) {
                        unsafe {
                            FindClose(find_handle)?;
                        }
                        drop(lock);
                        return Err(e);
                    }
                    if let Err(e) =
                        unsafe { FindNextFileW(find_handle, &mut find_data) }
                     {
                        break;
                    }
                }
                unsafe {
                    FindClose(find_handle)?;
                }
                drop(lock);
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<()> {
        let full_path = {
            let file_name = OsString::from_wide(file_name.as_slice());
            let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
            if full_path.len() > FULLPATH_SIZE {
                return Err(STATUS_OBJECT_NAME_INVALID.into());
            }
            U16CString::from_os_str_truncate(full_path)
        };

        let new_full_path = {
            let new_file_name = OsString::from_wide(new_file_name.as_slice());
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

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
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
            context.handle(),
            FileBasicInfo,
            (&basic_info as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        ));

        self.get_file_info_internal(context.handle(), file_info)
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<()> {
        let disposition_info = FILE_DISPOSITION_INFO {
            DeleteFile: BOOLEAN(if delete_file { 1 } else { 0 }),
        };

        win32_try!(unsafe SetFileInformationByHandle(context.handle(),
            FileDispositionInfo, (&disposition_info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32));
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        if set_allocation_size {
            let allocation_info = FILE_ALLOCATION_INFO {
                AllocationSize: new_size as i64,
            };

            win32_try!(unsafe SetFileInformationByHandle(
                context.handle(),
                FileAllocationInfo,
                (&allocation_info as *const FILE_ALLOCATION_INFO).cast(),
                std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32
            ))
        } else {
            let eof_info = FILE_END_OF_FILE_INFO {
                EndOfFile: new_size as i64,
            };

            win32_try!(unsafe SetFileInformationByHandle(
                context.handle(),
                FileEndOfFileInfo,
                (&eof_info as *const FILE_END_OF_FILE_INFO).cast(),
                std::mem::size_of::<FILE_END_OF_FILE_INFO>() as u32
            ))
        }
        self.get_file_info_internal(context.handle(), file_info)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        if constrained_io {
            let mut fsize = 0;
            win32_try!(unsafe GetFileSizeEx(context.handle(), &mut fsize));

            if offset >= fsize as u64 {
                return Ok(0);
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
            context.handle(),
            Some(buffer),
            Some(&mut bytes_transferred),
            Some(&mut overlapped),
        ));

        self.get_file_info_internal(context.handle(), file_info)?;
        Ok(bytes_transferred)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> Result<()> {
        let mut root = [0u16; MAX_PATH as usize];
        let mut total_size = 0u64;
        let mut free_size = 0u64;
        let fname = U16CString::from_os_str_truncate(self.path.as_os_str());
        win32_try!(unsafe GetVolumePathNameW(PCWSTR(fname.as_ptr()), &mut root[..]));
        win32_try!(unsafe GetDiskFreeSpaceExW(
            PCWSTR(U16CStr::from_slice_truncate(&root).unwrap().as_ptr()),
            None,
            Some(&mut total_size),
            Some(&mut free_size),
        ));

        out_volume_info.total_size = total_size;
        out_volume_info.free_size = free_size;
        out_volume_info.set_volume_label(VOLUME_LABEL);

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
        let mut volume_params = VolumeParams::new(FileContextMode::Descriptor);

        volume_params
            .sector_size(ALLOCATION_UNIT)
            .sectors_per_allocation_unit(1)
            .volume_creation_time(metadata.creation_time())
            .volume_serial_number(0)
            .file_info_timeout(100)
            .case_sensitive_search(false)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(true)
            .post_cleanup_when_modified_only(true)
            .pass_query_directory_pattern(true)
            .flush_and_purge_on_cleanup(true)
            .prefix(volume_prefix)
            .filesystem_name("ptfs-winfsp-rs");

        // let context = NtPassthroughContext::new(canonical_path);
        let context = PtfsContext {
            path: canonical_path.into_os_string(),
        };

        Ok(Ptfs {
            fs: FileSystemHost<PtfsContext>::new(volume_params, context)?,
        })
    }
}
