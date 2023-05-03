use crate::fs::file::NtPassthroughFile;
use crate::native::lfs::LfsRenameSemantics;
use crate::native::{lfs, volume};
use ntapi::ntioapi::{
    FileIdBothDirectoryInformation, FILE_ID_BOTH_DIR_INFORMATION, FILE_OVERWRITE,
    FILE_STREAM_INFORMATION, FILE_SUPERSEDE,
};
use ntapi::winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_WRITE_DATA,
    MAXIMUM_ALLOWED,
};

use std::ffi::OsString;
use std::mem::size_of;

use ntapi::winapi::um::winioctl::{
    FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT,
};
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::addr_of;

use widestring::{u16cstr, U16CString};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, INVALID_HANDLE_VALUE, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED,
    STATUS_NOT_A_DIRECTORY, STATUS_SHARING_VIOLATION,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_ID_BOTH_DIR_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::WindowsProgramming::{
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::Storage::FileSystem::FILE_CREATE;
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use winfsp::constants::FspCleanupFlags::FspCleanupDelete;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, IoResult, OpenFileInfo,
    StreamInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::VolumeParams;
use winfsp::util::Win32SafeHandle;
use winfsp::FspError;
use winfsp::U16CStr;

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
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
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
        let root_prefix = lfs::lfs_get_file_name(*root_handle)?;
        let root_prefix_len = (root_prefix.len() * size_of::<u16>()) as u32;

        Ok(Self {
            root_handle,
            root_prefix_len,
            root_osstring: root.as_ref().to_path_buf().into_os_string(),
            root_prefix: U16CString::from_vec(root_prefix).expect("invalid root path"),
            set_alloc_size_on_cleanup: true,
        })
    }

    pub fn new_with_volume_params(
        root: impl AsRef<Path>,
        volume_params: &mut VolumeParams,
    ) -> winfsp::Result<Self> {
        volume_params.volume_creation_time({
            let metadata = std::fs::metadata(&root)?;
            if !metadata.is_dir() {
                return Err(STATUS_NOT_A_DIRECTORY.into());
            }
            metadata.creation_time()
        });

        let context = Self::new(root)?;
        let fs_attr = volume::get_attr(*context.root_handle)?;
        let fs_sz = volume::get_size(*context.root_handle)?;

        volume_params
            .sector_size(fs_sz.BytesPerSector as u16)
            .sectors_per_allocation_unit(fs_sz.SectorsPerAllocationUnit as u16)
            .max_component_length(unsafe { fs_attr.as_ref().MaximumComponentNameLength } as u16)
            .case_sensitive_search(false)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(true)
            .post_cleanup_when_modified_only(false)
            .always_use_double_buffering(true)
            .pass_query_directory_pattern(true)
            .flush_and_purge_on_cleanup(true)
            .wsl_features(true)
            .reparse_points(true)
            .stream_info_timeout(1000)
            .named_streams(true)
            .file_info_timeout(1000);

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

        dir_info.set_name_raw(file_name_slice)?;

        let file_info = dir_info.file_info_mut();

        file_info.file_attributes = unsafe { addr_of!((*query_info).FileAttributes).read() };
        file_info.reparse_tag = if FILE_ATTRIBUTE_REPARSE_POINT & file_info.file_attributes != 0 {
            unsafe { addr_of!((*query_info).EaSize).read() }
        } else {
            0
        };

        file_info.allocation_size = unsafe { addr_of!((*query_info).AllocationSize).read() } as u64;
        file_info.file_size = unsafe { addr_of!((*query_info).EndOfFile).read() } as u64;
        file_info.creation_time = unsafe { addr_of!((*query_info).CreationTime).read() } as u64;
        file_info.last_access_time =
            unsafe { addr_of!((*query_info).LastAccessTime).read() } as u64;
        file_info.last_write_time = unsafe { addr_of!((*query_info).LastWriteTime).read() } as u64;
        file_info.change_time = unsafe { addr_of!((*query_info).ChangeTime).read() } as u64;
        file_info.index_number = unsafe { addr_of!((*query_info).FileId).read() } as u64;
        file_info.hard_links = 0;
        file_info.ea_size = if FILE_ATTRIBUTE_REPARSE_POINT & file_info.file_attributes != 0 {
            lfs::lfs_get_ea_size(unsafe { addr_of!((*query_info).EaSize).read() })
        } else {
            0
        };

        Ok(())
    }
}

impl FileSystemContext for NtPassthroughContext {
    type FileContext = NtPassthroughFile;

    fn get_security_by_name<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
        resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        if let Some(security) = resolve_reparse_points(file_name.as_ref()) {
            return Ok(security);
        }
        let handle = lfs::lfs_open_file(
            *self.root_handle,
            file_name.as_ref(),
            READ_CONTROL.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
        )?;

        let attributes = lfs::lfs_get_file_attributes(*handle)?;

        // cache file_attributes for Open
        unsafe {
            self.with_operation_response(|rsp| {
                rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
            })
            .unwrap();
        }

        let needed_size = if let Some(descriptor_len) = descriptor_len {
            lfs::lfs_get_security(
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

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: needed_size as u64,
            attributes,
        })
    }

    fn open<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
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
            FILE_ACCESS_RIGHTS(MAXIMUM_ALLOWED)
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

        let result = lfs::lfs_open_file(
            *self.root_handle,
            file_name.as_ref(),
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
                file_name.as_ref(),
                backup_access,
                FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            ),
            Err(e) => Err(e),
        }?;

        let file_size = file_info.as_ref().file_size;
        lfs::lfs_get_file_info(*handle, Some(self.root_prefix_len), file_info)?;

        Ok(Self::FileContext::new(handle, file_size, is_directory))
    }

    fn close(&self, context: Self::FileContext) {
        context.close()
    }

    fn create<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let is_directory = create_options & FILE_DIRECTORY_FILE != 0;

        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_RIGHTS(MAXIMUM_ALLOWED)
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

        let result = lfs::lfs_create_file(
            *self.root_handle,
            file_name.as_ref(),
            maximum_access.0,
            security_descriptor,
            allocation_size.as_mut(),
            file_attributes.0,
            FILE_CREATE,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            &extra_buffer,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER))
                if maximum_access.0 == MAXIMUM_ALLOWED =>
            {
                lfs::lfs_create_file(
                    *self.root_handle,
                    file_name.as_ref(),
                    maximum_access.0,
                    security_descriptor,
                    allocation_size.as_mut(),
                    file_attributes.0,
                    FILE_CREATE,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                    &extra_buffer,
                )
            }
            Err(e) => Err(e),
        }?;

        if let Some(extra_buffer) = extra_buffer && extra_buffer_is_reparse_point {
            lfs::lfs_fs_control_file(*handle, FSCTL_SET_REPARSE_POINT, Some(extra_buffer), None)?;
        }

        let file_size = file_info.as_ref().file_size;
        lfs::lfs_get_file_info(*handle, Some(self.root_prefix_len), file_info)?;

        Ok(Self::FileContext::new(handle, file_size, is_directory))
    }

    fn cleanup<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: Option<P>,
        flags: u32,
    ) {
        if FspCleanupDelete.is_flagged(flags) {
            // ignore errors..
            lfs::lfs_set_delete(context.handle(), true).unwrap_or(());
            context.invalidate();
        } else if self.set_alloc_size_on_cleanup {
            if let Ok(fsize) = lfs::lfs_get_file_size(context.handle()) {
                lfs::lfs_set_allocation_size(context.handle(), fsize).unwrap_or(());
            }
        }
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
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
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<u64> {
        let needed_size = if let Some(descriptor_len) = descriptor_len {
            lfs::lfs_get_security(
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

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> winfsp::Result<()> {
        lfs::lfs_set_security(
            context.handle(),
            security_information,
            modification_descriptor,
        )
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut allocation_size = if allocation_size != 0 {
            Some(allocation_size as i64)
        } else {
            None
        };

        let new_handle = lfs::lfs_create_file(
            context.handle(),
            u16cstr!(""),
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
            &extra_buffer,
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

    fn read_directory<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        pattern: Option<P>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // windows struct is easier to work with, but make sure it's the same layout.
        const _: () = assert!(
            size_of::<FILE_ID_BOTH_DIR_INFORMATION>() == size_of::<FILE_ID_BOTH_DIR_INFO>()
        );

        let dir_size = context.dir_size();
        let handle = context.handle();
        let pattern = pattern.map(|p| PCWSTR(p.as_ref().as_ptr()));
        let mut dirinfo: DirInfo = DirInfo::new();
        if let Ok(dirbuffer) = context
            .dir_buffer()
            .acquire(marker.is_none(), Some(dir_size))
        {
            // todo: don't reallocate this.
            let mut query_buffer = vec![0u8; 16 * 1024];
            let mut restart_scan = true;

            'once: loop {
                query_buffer.fill(0);
                if let Ok(bytes_transferred) = lfs::lfs_query_directory_file(
                    handle,
                    &mut query_buffer,
                    FileIdBothDirectoryInformation as i32,
                    false,
                    &pattern,
                    restart_scan,
                ) {
                    let mut query_buffer_cursor =
                        query_buffer.as_ptr() as *const FILE_ID_BOTH_DIR_INFO;
                    'inner: loop {
                        // SAFETY: FILE_ID_BOTH_DIR_INFO has FileName as the last VST array member, so it's offset is size_of - 1.
                        // bounds check to ensure we don't go past the edge of the buffer.
                        if query_buffer
                            .as_ptr()
                            .map_addr(|addr| addr.wrapping_add(bytes_transferred))
                            < (query_buffer_cursor as *const _ as *const u8).map_addr(|addr| {
                                addr.wrapping_add(size_of::<FILE_ID_BOTH_DIR_INFO>() - 1)
                            })
                        {
                            break 'once;
                        }
                        Self::copy_query_info_to_dirinfo(query_buffer_cursor, &mut dirinfo)?;
                        dirbuffer.write(&mut dirinfo)?;

                        unsafe {
                            let query_next =
                                addr_of!((*query_buffer_cursor).NextEntryOffset).read();
                            if query_next == 0 {
                                break 'inner;
                            }
                            query_buffer_cursor = (query_buffer_cursor as *const _ as *const u8)
                                .map_addr(|addr| addr.wrapping_add(query_next as usize))
                                .cast();
                        }
                    }
                    restart_scan = false;
                } else {
                    break 'once;
                }
            }
        }
        Ok(context.dir_buffer().read(marker, buffer))
    }

    fn rename<P: AsRef<U16CStr>>(
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

        // skip first char
        let new_file_name = &new_file_name.as_ref()[1..];
        lfs::lfs_rename(
            *self.root_handle,
            context.handle(),
            new_file_name,
            replace_mode,
        )
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

    fn set_delete<P: AsRef<U16CStr>>(
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
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if set_allocation_size {
            lfs::lfs_set_allocation_size(context.handle(), new_size)?;
        } else {
            lfs::lfs_set_eof(context.handle(), new_size)?;
        }

        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<IoResult> {
        if constrained_io {
            let fsize = lfs::lfs_get_file_size(context.handle())?;
            if offset >= fsize {
                return Ok(IoResult {
                    bytes_transferred: 0,
                    io_pending: false,
                });
            }

            if offset + buffer.len() as u64 > fsize {
                buffer = &buffer[0..(fsize - offset) as usize]
            }
        }

        let bytes_read = lfs::lfs_write_file(context.handle(), buffer, offset)?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)?;
        Ok(IoResult {
            bytes_transferred: bytes_read as u32,
            io_pending: false,
        })
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let vol_info = lfs::lfs_get_volume_info(*self.root_handle)?;
        out_volume_info.total_size = vol_info.total_size;
        out_volume_info.free_size = vol_info.free_size;
        Ok(())
    }

    fn get_stream_info(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let mut query_buffer = vec![0u8; 16 * 1024];
        let mut buffer_cursor = 0;
        let mut stream_info: StreamInfo = StreamInfo::new();
        let bytes_transferred = lfs::lfs_get_stream_info(context.handle(), &mut query_buffer)?;

        let mut query_buffer_cursor = query_buffer.as_ptr() as *const FILE_STREAM_INFORMATION;
        loop {
            // SAFETY: FILE_STREAM_INFORMATION has StreamName as the last VST array member, so it's offset is size_of - 1.
            // bounds check to ensure we don't go past the edge of the buffer.
            if query_buffer
                .as_ptr()
                .map_addr(|addr| addr.wrapping_add(bytes_transferred))
                < (query_buffer_cursor as *const _ as *const u8)
                    .map_addr(|addr| addr.wrapping_add(size_of::<FILE_STREAM_INFORMATION>() - 1))
            {
                break;
            }

            unsafe {
                let name_length = addr_of!((*query_buffer_cursor).StreamNameLength).read();
                let mut stream_name_slice = {
                    let stream_name_ptr = addr_of!((*query_buffer_cursor).StreamName) as *const u16;
                    std::slice::from_raw_parts(
                        stream_name_ptr,
                        name_length
                            .checked_div(std::mem::size_of::<u16>() as u32)
                            .expect("Passed in stream name length of 0 from Windows!!")
                            as usize,
                    )
                };
                if stream_name_slice.first().cloned() == Some(b':' as u16) {
                    stream_name_slice = &stream_name_slice[1..]
                }

                stream_info.set_name_raw(stream_name_slice)?;
            }

            unsafe {
                stream_info.stream_size = *addr_of!((*query_buffer_cursor).StreamSize)
                    .read()
                    .QuadPart() as u64;
                stream_info.stream_alloc_size =
                    *addr_of!((*query_buffer_cursor).StreamAllocationSize)
                        .read()
                        .QuadPart() as u64;
            }

            if !stream_info.append_to_buffer(buffer, &mut buffer_cursor) {
                return Ok(buffer_cursor);
            }

            unsafe {
                let query_next = addr_of!((*query_buffer_cursor).NextEntryOffset).read();
                if query_next == 0 {
                    break;
                }
                query_buffer_cursor = (query_buffer_cursor as *const _ as *const u8)
                    .map_addr(|addr| addr.wrapping_add(query_next as usize))
                    .cast();
            }
        }

        StreamInfo::<255>::finalize_buffer(buffer, &mut buffer_cursor);
        Ok(buffer_cursor)
    }

    fn get_reparse_point_by_name<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let reparse_handle = lfs::lfs_open_file(
            *self.root_handle,
            file_name,
            0,
            FILE_OPEN_FOR_BACKUP_INTENT
                | FILE_OPEN_REPARSE_POINT
                | if is_directory { FILE_DIRECTORY_FILE } else { 0 },
        )?;
        let result =
            lfs::lfs_fs_control_file(*reparse_handle, FSCTL_GET_REPARSE_POINT, None, Some(buffer));

        match result {
            Err(FspError::NTSTATUS(STATUS_BUFFER_OVERFLOW)) => Err(STATUS_BUFFER_TOO_SMALL.into()),
            Err(e) => Err(e),
            Ok(bytes) => Ok(bytes as u64),
        }
    }

    fn get_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let result = lfs::lfs_fs_control_file(
            context.handle(),
            FSCTL_GET_REPARSE_POINT,
            None,
            Some(buffer),
        );
        match result {
            Err(FspError::NTSTATUS(STATUS_BUFFER_OVERFLOW)) => Err(STATUS_BUFFER_TOO_SMALL.into()),
            Err(e) => Err(e),
            Ok(bytes) => Ok(bytes as u64),
        }
    }

    fn set_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        lfs::lfs_fs_control_file(
            context.handle(),
            FSCTL_SET_REPARSE_POINT,
            Some(buffer),
            None,
        )?;
        Ok(())
    }

    fn delete_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        lfs::lfs_fs_control_file(
            context.handle(),
            FSCTL_DELETE_REPARSE_POINT,
            Some(buffer),
            None,
        )?;
        Ok(())
    }

    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        Ok(lfs::lfs_get_ea(context.handle(), buffer) as u32)
    }

    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        lfs::lfs_set_ea(context.handle(), buffer)?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }
}
