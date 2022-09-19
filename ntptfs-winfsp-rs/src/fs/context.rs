use crate::fs::file::NtPassthroughFile;
use crate::native::lfs::LfsRenameSemantics;
use crate::native::{lfs, volume};
use ntapi::ntioapi::{
    FileIdBothDirectoryInformation, FILE_ID_BOTH_DIR_INFORMATION, FILE_OVERWRITE, FILE_SUPERSEDE,
};
use ntapi::winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_WRITE_DATA,
    MAXIMUM_ALLOWED,
};

use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::addr_of;
use widestring::U16CString;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::w;
use windows::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_SHARING_VIOLATION,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_FLAGS,
    FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OVERLAPPED, FILE_ID_BOTH_DIR_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::WindowsProgramming::{
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::Storage::FileSystem::FILE_CREATE;
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use winfsp::error::FspError;
use winfsp::filesystem::constants::FspCleanupFlags::FspCleanupDelete;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileSecurity, FileSystemContext, IoResult, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS, MAX_PATH,
};
use winfsp::util::Win32SafeHandle;

const VOLUME_LABEL: &HSTRING = w!("Snowflake");

#[repr(C)]
#[derive(Debug)]
pub struct NtPassthroughContext {
    root_handle: Win32SafeHandle,
    root_prefix_len: u32,
    root_prefix: U16CString,
    root_osstring: OsString,
    set_alloc_size_on_cleanup: bool,
}

impl NtPassthroughContext {
    pub fn new(root: impl AsRef<Path>) -> winfsp::Result<Self> {
        let path = root.as_ref();
        let path = HSTRING::from(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                &path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                None,
            )?
        };

        if handle == INVALID_HANDLE_VALUE {
            unsafe { return Err(GetLastError().into()) }
        }

        eprintln!("ntpfs: {:?} @ {:?}", handle, path);
        Self::new_from_handle(Win32SafeHandle::from(handle), root)
    }

    pub fn new_from_handle(
        root_handle: Win32SafeHandle,
        root: impl AsRef<Path>,
    ) -> winfsp::Result<Self> {
        let root_prefix = lfs::lfs_query_file_name(*root_handle)?;
        let root_prefix_len = (root_prefix.len() * size_of::<u16>()) as u32;

        dbg!(Ok(Self {
            root_handle,
            root_prefix_len,
            root_osstring: root.as_ref().to_path_buf().into_os_string(),
            root_prefix: U16CString::from_vec(root_prefix).expect("invalid root path"),
            set_alloc_size_on_cleanup: false,
        }))
    }

    pub fn new_with_volume_params(
        root: impl AsRef<Path>,
        volume_params: &mut FSP_FSCTL_VOLUME_PARAMS,
    ) -> winfsp::Result<Self> {
        volume_params.VolumeCreationTime = {
            let metadata = std::fs::metadata(&root)?;
            if !metadata.is_dir() {
                return Err(STATUS_NOT_A_DIRECTORY.into());
            }
            metadata.creation_time()
        };

        let context = Self::new(root)?;
        let fs_attr = volume::get_attr(*context.root_handle)?;
        let fs_sz = volume::get_size(*context.root_handle)?;

        volume_params.SectorSize = fs_sz.BytesPerSector as u16;
        volume_params.SectorsPerAllocationUnit = fs_sz.SectorsPerAllocationUnit as u16;
        volume_params.MaxComponentLength =
            unsafe { fs_attr.as_ref().MaximumComponentNameLength } as u16;
        volume_params.set_CaseSensitiveSearch(0);
        volume_params.set_CasePreservedNames(1);
        volume_params.set_UnicodeOnDisk(1);
        volume_params.set_PersistentAcls(1);
        volume_params.set_PostCleanupWhenModifiedOnly(1);
        volume_params.set_PassQueryDirectoryPattern(1);
        volume_params.set_FlushAndPurgeOnCleanup(1);
        volume_params.set_RejectIrpPriorToTransact0(1);
        volume_params.set_UmFileContextIsUserContext2(1);

        Ok(context)
    }

    fn copy_query_info_to_dirinfo<const DIR_INFO_SIZE: usize>(
        query_info: *const FILE_ID_BOTH_DIR_INFO,
        dir_info: &mut DirInfo<DIR_INFO_SIZE>,
    ) -> winfsp::Result<()> {
        dir_info.reset();

        let file_name_slice = unsafe {
            let file_name_ptr = addr_of!((*query_info).FileName) as *const u16;
            std::slice::from_raw_parts(
                file_name_ptr,
                addr_of!((*query_info).FileNameLength)
                    .read()
                    .checked_div(std::mem::size_of::<u16>() as u32)
                    .expect("Passed in file name length of 0 from Windows!!")
                    as usize,
            )
        };

        // todo: check null termination
        unsafe { dir_info.set_file_name_raw(file_name_slice)? }

        let file_info = dir_info.file_info_mut();

        file_info.FileAttributes = unsafe { addr_of!((*query_info).FileAttributes).read() };
        file_info.ReparseTag = if FILE_ATTRIBUTE_REPARSE_POINT & file_info.FileAttributes != 0 {
            unsafe { addr_of!((*query_info).EaSize).read() }
        } else {
            0
        };

        file_info.AllocationSize = unsafe { addr_of!((*query_info).AllocationSize).read() } as u64;
        file_info.FileSize = unsafe { addr_of!((*query_info).EndOfFile).read() } as u64;
        file_info.CreationTime = unsafe { addr_of!((*query_info).CreationTime).read() } as u64;
        file_info.LastAccessTime = unsafe { addr_of!((*query_info).LastAccessTime).read() } as u64;
        file_info.LastWriteTime = unsafe { addr_of!((*query_info).LastWriteTime).read() } as u64;
        file_info.ChangeTime = unsafe { addr_of!((*query_info).ChangeTime).read() } as u64;
        // file_info.IndexNumber = unsafe { addr_of!((*query_info).FileId).read() } as u64;
        file_info.HardLinks = 0;
        file_info.EaSize = if FILE_ATTRIBUTE_REPARSE_POINT & file_info.FileAttributes != 0 {
            lfs::lfs_get_ea_size(unsafe { addr_of!((*query_info).EaSize).read() })
        } else {
            0
        };

        Ok(())
    }
}

macro_rules! win32_try {
    (unsafe $e:expr) => {
        if unsafe { !($e).as_bool() } {
            return Err(::winfsp::error::FspError::from(unsafe { GetLastError() }));
        }
    };
}

const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
        / std::mem::size_of::<u16>());

#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

impl NtPassthroughContext {
    fn get_file_info_internal(
        &self,
        file_handle: HANDLE,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        win32_try!(unsafe GetFileInformationByHandle(file_handle, &mut os_file_info));

        file_info.FileAttributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = quadpart(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.AllocationSize = (file_info.FileSize + 4096_u64 - 1) / 4096_u64 * 4096_u64;
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

impl FileSystemContext for NtPassthroughContext {
    type FileContext = NtPassthroughFile;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        // todo: reparse
        let file_name = HSTRING::from(file_name.as_ref());
        eprintln!("{:?}", file_name);
        let handle = lfs::lfs_open_file(
            *self.root_handle,
            PCWSTR(file_name.as_ptr()),
            READ_CONTROL.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
        )?;

        let attributes = lfs::lfs_query_file_attributes(*handle)?;

        // cache FileAttributes for Open
        unsafe {
            self.with_operation_response(|rsp| {
                rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
            })
            .unwrap();
        }

        let needed_size = if let Some(descriptor_len) = descriptor_len {
            lfs::lfs_query_security(
                *handle,
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len as u32,
            )?
        } else {
            0
        };

        eprintln!("gsbn ok");
        dbg!(Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: needed_size as u64,
            attributes,
        }))
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        let backup_access = granted_access.0;

        let is_directory = unsafe {
            self.with_operation_response(|ctx| {
                FILE_ATTRIBUTE_DIRECTORY & ctx.Rsp.Create.Opened.FileInfo.FileAttributes != 0
            })
        }
        .unwrap_or(false);

        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_FLAGS(MAXIMUM_ALLOWED)
        };

        let mut create_options =
            create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        // WORKAROUND:
        // WOW64 appears to have a bug in some versions of the OS (seen on Win10 1909 and
        // Server 2012 R2), where NtQueryDirectoryFile may produce garbage if called on a
        // directory that has been opened without FILE_SYNCHRONOUS_IO_NONALERT.
        //
        // Garbage:
        // after a STATUS_PENDING has been waited, Iosb.Information reports bytes transferred
        // but the buffer does not get filled

        // Always open directories in a synchronous manner.

        if is_directory {
            maximum_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        let file_name = HSTRING::from(file_name.as_ref());

        let result = lfs::lfs_open_file(
            *self.root_handle,
            PCWSTR(file_name.as_ptr()),
            maximum_access.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(
                STATUS_ACCESS_DENIED
                | STATUS_MEDIA_WRITE_PROTECTED
                | STATUS_SHARING_VIOLATION
                | STATUS_INVALID_PARAMETER,
            )) if maximum_access.0 == MAXIMUM_ALLOWED => lfs::lfs_open_file(
                *self.root_handle,
                PCWSTR(file_name.as_ptr()),
                backup_access,
                FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            ),
            Err(e) => Err(e),
        }?;

        lfs::lfs_get_file_info(*handle, Some(self.root_prefix_len), file_info)?;

        eprintln!("opn ok");
        eprintln!("{:?} {:?}", file_info, handle);
        dbg!(Ok(Self::FileContext::new(
            handle,
            file_info.FileSize,
            is_directory,
        )))
    }

    fn create<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        let is_directory = create_options & FILE_DIRECTORY_FILE != 0;

        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_FLAGS(MAXIMUM_ALLOWED)
        };

        let mut create_options =
            create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        // WORKAROUND:
        // WOW64 appears to have a bug in some versions of the OS (seen on Win10 1909 and
        // Server 2012 R2), where NtQueryDirectoryFile may produce garbage if called on a
        // directory that has been opened without FILE_SYNCHRONOUS_IO_NONALERT.
        //
        // Garbage:
        // after a STATUS_PENDING has been waited, Iosb.Information reports bytes transferred
        // but the buffer does not get filled

        // Always open directories in a synchronous manner.

        if is_directory {
            maximum_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        let mut allocation_size = if allocation_size != 0 {
            Some(allocation_size as i64)
        } else {
            None
        };

        let file_attributes = if file_attributes.0 == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            file_attributes
        };

        let file_name = HSTRING::from(file_name.as_ref());

        let result = lfs::lfs_create_file(
            *self.root_handle,
            PCWSTR(file_name.as_ptr()),
            maximum_access.0,
            security_descriptor,
            allocation_size.as_mut(),
            file_attributes.0,
            FILE_CREATE,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            // todo: ea
            &mut None,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER))
                if maximum_access.0 == MAXIMUM_ALLOWED =>
            {
                lfs::lfs_create_file(
                    *self.root_handle,
                    PCWSTR(file_name.as_ptr()),
                    maximum_access.0,
                    security_descriptor,
                    allocation_size.as_mut(),
                    file_attributes.0,
                    FILE_CREATE,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                    &mut None,
                )
            }
            Err(e) => Err(e),
        }?;

        // todo: WSL features

        lfs::lfs_get_file_info(*handle, Some(self.root_prefix_len), file_info)?;

        eprintln!("cr ok");
        Ok(Self::FileContext::new(
            handle,
            file_info.FileSize,
            is_directory,
        ))
    }

    fn close(&self, context: Self::FileContext) {
        eprintln!("cl ok");
        context.close()
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        let mut allocation_size = if allocation_size != 0 {
            Some(allocation_size as i64)
        } else {
            None
        };

        let new_handle = lfs::lfs_create_file(
            context.handle(),
            windows::w!(""),
            if replace_file_attributes {
                DELETE
            } else {
                FILE_WRITE_DATA
            },
            PSECURITY_DESCRIPTOR::default(),
            allocation_size.as_mut(),
            (if replace_file_attributes {
                if file_attributes.0 == 0 {
                    FILE_ATTRIBUTE_NORMAL
                } else {
                    file_attributes
                }
            } else {
                file_attributes
            })
            .0,
            if replace_file_attributes {
                FILE_SUPERSEDE
            } else {
                FILE_OVERWRITE
            },
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
            &mut None,
        )?;

        // explicit close handle.
        drop(new_handle);

        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<IoResult> {
        let bytes_read = lfs::lfs_read_file(context.handle(), buffer, offset)?;
        Ok(IoResult {
            bytes_transferred: bytes_read as u32,
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
    ) -> winfsp::Result<IoResult> {
        if constrained_io {
            let fsize = lfs::lfs_query_file_size(context.handle())?;
            if offset >= fsize {
                return Ok(IoResult {
                    bytes_transferred: 0,
                    io_pending: false,
                });
            }

            if offset + buffer.len() as u64 > fsize {
                buffer = &buffer[0..(fsize as u64 - offset) as usize]
            }
        }

        let bytes_read = lfs::lfs_write_file(context.handle(), buffer, offset)?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)?;
        Ok(IoResult {
            bytes_transferred: bytes_read as u32,
            io_pending: false,
        })
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        if context.is_none() {
            return Ok(());
        }
        let context = context.unwrap();
        lfs::lfs_flush(context.handle())?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn rename<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        new_file_name: P,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let replace_mode = if replace_if_exists
            && (!context.is_directory()
                || unsafe {
                    self.with_operation_request(|f| {
                        (2 /*POSIX_SEMANTICS*/ & f.Req.SetInformation.Info.RenameEx.Flags) != 0
                    })
                }
                .unwrap_or(false))
        {
            LfsRenameSemantics::PosixReplaceSemantics
        } else if replace_if_exists {
            LfsRenameSemantics::NtReplaceSemantics
        } else {
            LfsRenameSemantics::DoNotReplace
        };

        let new_filename = HSTRING::from(new_file_name.as_ref());
        lfs::lfs_rename(
            *self.root_handle,
            context.handle(),
            new_filename,
            replace_mode,
        )
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<u64> {
        let needed_size = if let Some(descriptor_len) = descriptor_len {
            lfs::lfs_query_security(
                context.handle(),
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len as u32,
            )?
        } else {
            0
        };

        Ok(needed_size as u64)
    }

    fn set_delete<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        lfs::lfs_set_delete(context.handle(), delete_file)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        if set_allocation_size {
            lfs::lfs_set_allocation_size(context.handle(), new_size)?;
        } else {
            lfs::lfs_set_eof(context.handle(), new_size)?;
        }

        lfs::lfs_get_file_info(context.handle(), None, file_info)
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
    ) -> winfsp::Result<()> {
        lfs::lfs_set_basic_info(
            context.handle(),
            file_attributes,
            creation_time,
            last_access_time,
            last_write_time,
            last_change_time,
        )?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn cleanup<P: AsRef<OsStr>>(
        &self,
        context: &mut Self::FileContext,
        _file_name: Option<P>,
        flags: u32,
    ) {
        if FspCleanupDelete.is_flagged(flags) {
            // ignore errors..
            lfs::lfs_set_delete(context.handle(), true).unwrap_or(());
            context.invalidate();
        } else if self.set_alloc_size_on_cleanup {
            if let Ok(fsize) = lfs::lfs_query_file_size(context.handle()) {
                lfs::lfs_set_allocation_size(context.handle(), fsize).unwrap_or(());
            }
        }
    }

    fn read_directory<P: Into<PCWSTR>>(
        &self,
        context: &mut Self::FileContext,
        pattern: Option<P>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // windows struct is easier to work with, but make sure it's the same layout.
        const _: () = assert!(
            size_of::<FILE_ID_BOTH_DIR_INFORMATION>() == size_of::<FILE_ID_BOTH_DIR_INFO>()
        );
        eprintln!("readdir entry");
        let dir_size = context.dir_size();
        let handle = context.handle();
        let pattern = pattern.map(|p| p.into());
        {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();
            let mut dirbuffer = context
                .dir_buffer()
                .acquire(marker.is_none(), Some(dir_size))?;
            // todo: don't reallocate this.
            let mut query_buffer = vec![0u8; 16 * 1024];
            let mut restart_scan = true;
            'once: while restart_scan {
                let bytes_transferred = lfs::lfs_query_directory_file(
                    handle,
                    &mut query_buffer,
                    FileIdBothDirectoryInformation as i32,
                    false,
                    &pattern,
                    restart_scan,
                )?;

                eprintln!("bfs: {:?}", bytes_transferred);
                eprintln!("expected: {:?}", size_of::<FILE_ID_BOTH_DIR_INFO>());
                let query_buffer = &query_buffer[..bytes_transferred];
                let mut query_buffer_cursor = query_buffer.as_ptr() as *const FILE_ID_BOTH_DIR_INFO;
                loop {
                    // SAFETY: FILE_ID_BOTH_DIR_INFO has FileName as the last VST array member, so it's offset is size_of - 1.
                    // bounds check to ensure we don't go past the edge of the buffer.
                    if query_buffer.as_ptr().wrapping_add(bytes_transferred)
                        < (query_buffer_cursor as *const _ as *const u8)
                            .wrapping_add(size_of::<FILE_ID_BOTH_DIR_INFO>() - 1)
                    {
                        break 'once;
                    }
                    Self::copy_query_info_to_dirinfo(query_buffer_cursor, &mut dirinfo)?;
                    dirbuffer.write(&mut dirinfo)?;

                    unsafe {
                        let query_next = addr_of!((*query_buffer_cursor).NextEntryOffset).read();
                        if query_next == 0 {
                            break;
                        }
                        query_buffer_cursor = (query_buffer_cursor as *const _ as *const u8)
                            .wrapping_add(query_next as usize)
                            .cast();
                    }
                }
                restart_scan = false;
            }
        }
        Ok(context.dir_buffer().read(marker, buffer))
    }

    fn get_volume_info(&self, _out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> winfsp::Result<()> {
        Ok(())
    }

    fn control(
        &self,
        _context: &Self::FileContext,
        _control_code: u32,
        _input: &[u8],
        _output: &mut [u8],
    ) -> winfsp::Result<u32> {
        todo!()
    }
    fn delete_reparse_point<P: AsRef<OsStr>>(
        &self,
        _context: &Self::FileContext,
        _file_name: P,
        _buffer: &[u8],
    ) -> winfsp::Result<()> {
        todo!()
    }
    fn set_volume_label<P: Into<PWSTR>>(
        &self,
        _volume_label: P,
        _volume_info: &mut FSP_FSCTL_VOLUME_INFO,
    ) -> winfsp::Result<()> {
        todo!()
    }
    fn get_dir_info_by_name<P: AsRef<OsStr>>(
        &self,
        _context: &Self::FileContext,
        _file_name: P,
        _out_dir_info: &mut DirInfo<MAX_PATH>,
    ) -> winfsp::Result<()> {
        todo!()
    }
    fn get_stream_info(
        &self,
        _context: &Self::FileContext,
        _buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        todo!()
    }
    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> winfsp::Result<()> {
        todo!()
    }
}
