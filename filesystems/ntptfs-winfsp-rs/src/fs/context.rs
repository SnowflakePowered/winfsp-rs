use crate::fs::file::NtPassthroughFile;
use crate::native::lfs::{LfsRenameSemantics, async_io};
use crate::native::{lfs, volume};
use std::ffi::OsString;
use std::future::Future;
use std::mem::{offset_of, size_of};

use std::os::raw::c_void;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::addr_of;
use widestring::{U16CString, u16cstr};
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION, FILE_NO_EA_KNOWLEDGE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE,
    FILE_STREAM_INFORMATION, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT,
    FileIdBothDirectoryInformation, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED,
    STATUS_NOT_A_DIRECTORY, STATUS_SHARING_VIOLATION,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Ioctl::{
    FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT,
};
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::core::{HSTRING, PCWSTR};

use winfsp::FspError;
use winfsp::U16CStr;
use winfsp::constants::FspCleanupFlags::FspCleanupDelete;
use winfsp::filesystem::{
    AsyncFileSystemContext, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    ModificationDescriptor, OpenFileInfo, StreamInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::VolumeParams;
use winfsp::util::{AtomicHandle, Win32HandleDrop};
#[repr(C)]
#[derive(Debug)]
/// The filesystem context for the NT passthrough filesystem.
pub struct NtPassthroughContext {
    root_handle: AtomicHandle<Win32HandleDrop>,
    root_prefix_len: u32,
    root_prefix: U16CString,
    root_osstring: OsString,
    set_alloc_size_on_cleanup: bool,
    executor: tokio::runtime::Runtime,
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
        Self::new_from_handle(AtomicHandle::from(handle), root)
    }

    pub fn new_from_handle(
        root_handle: AtomicHandle<Win32HandleDrop>,
        root: impl AsRef<Path>,
    ) -> winfsp::Result<Self> {
        let root_prefix = lfs::lfs_get_file_name(HANDLE(root_handle.handle()))?;
        let root_prefix_len = (root_prefix.len() * size_of::<u16>()) as u32;

        Ok(Self {
            root_handle,
            root_prefix_len,
            root_osstring: root.as_ref().to_path_buf().into_os_string(),
            root_prefix: U16CString::from_vec(root_prefix).expect("invalid root path"),
            set_alloc_size_on_cleanup: true,
            executor: tokio::runtime::Runtime::new().expect("couldn't boot tokio"),
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
        let fs_attr = volume::get_attr(HANDLE(context.root_handle.handle()))?;
        let fs_sz = volume::get_size(HANDLE(context.root_handle.handle()))?;

        volume_params
            .sector_size(fs_sz.BytesPerSector as u16)
            .sectors_per_allocation_unit(fs_sz.SectorsPerAllocationUnit as u16)
            .max_component_length(unsafe { fs_attr.as_ref().MaximumComponentNameLength } as u16)
            .case_sensitive_search(false)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(true)
            .post_cleanup_when_modified_only(true)
            .pass_query_directory_pattern(true)
            .flush_and_purge_on_cleanup(true)
            .wsl_features(true)
            .reparse_points(true)
            .named_streams(true)
            .file_info_timeout(u32::MAX)
            .allow_open_in_kernel_mode(true)
            .supports_posix_unlink_rename(true)
            .post_disposition_only_when_necessary(true);

        Ok(context)
    }

    fn copy_query_info_to_dirinfo<const DIR_INFO_SIZE: usize>(
        query_info: *const FILE_ID_BOTH_DIR_INFORMATION,
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
        file_info.reparse_tag = if FILE_ATTRIBUTE_REPARSE_POINT.0 & file_info.file_attributes != 0 {
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
        file_info.ea_size = if FILE_ATTRIBUTE_REPARSE_POINT.0 & file_info.file_attributes != 0 {
            lfs::lfs_get_ea_size(unsafe { addr_of!((*query_info).EaSize).read() })
        } else {
            0
        };

        Ok(())
    }
}

impl Drop for NtPassthroughContext {
    fn drop(&mut self) {
        println!("NtPassthroughContext was dropped!");
    }
}

impl FileSystemContext for NtPassthroughContext {
    type FileContext = NtPassthroughFile;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        // println!("gsbn: {file_name:?}\n");

        if let Some(security) = resolve_reparse_points(file_name) {
            return Ok(security);
        }
        let handle = lfs::lfs_open_file(
            HANDLE(self.root_handle.handle()),
            file_name,
            READ_CONTROL,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
        )?;

        let attributes = lfs::lfs_get_file_attributes(HANDLE(handle.handle()))?;

        // cache file_attributes for Open
        unsafe {
            self.with_operation_response(|rsp| {
                rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
            })
            .unwrap();
        }

        let needed_size = if let Some(security_descriptor) = security_descriptor {
            lfs::lfs_get_security(
                HANDLE(handle.handle()),
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                PSECURITY_DESCRIPTOR(security_descriptor.as_mut_ptr()),
                security_descriptor.len() as u32,
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

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        // println!("open: {file_name:?}\n");
        let backup_access = FILE_ACCESS_RIGHTS(granted_access);

        let is_directory = unsafe {
            self.with_operation_response(|ctx| {
                FILE_ATTRIBUTE_DIRECTORY.0 & ctx.Rsp.Create.Opened.FileInfo.FileAttributes != 0
            })
        }
        .unwrap_or(false);

        let mut maximum_access = if is_directory {
            FILE_ACCESS_RIGHTS(granted_access)
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_RIGHTS(MAXIMUM_ALLOWED)
        };

        let mut create_options = NTCREATEFILE_CREATE_OPTIONS(create_options)
            & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

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
            HANDLE(self.root_handle.handle()),
            file_name,
            maximum_access,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(err)
                if maximum_access.0 == MAXIMUM_ALLOWED
                    && (err.to_ntstatus() == STATUS_ACCESS_DENIED.0
                        || err.to_ntstatus() == STATUS_MEDIA_WRITE_PROTECTED.0
                        || err.to_ntstatus() == STATUS_SHARING_VIOLATION.0
                        || err.to_ntstatus() == STATUS_INVALID_PARAMETER.0) =>
            {
                lfs::lfs_open_file(
                    HANDLE(self.root_handle.handle()),
                    file_name,
                    backup_access,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                )
            }
            Err(e) => Err(e),
        }?;

        let file_size = file_info.as_ref().file_size;
        lfs::lfs_get_file_info(
            HANDLE(handle.handle()),
            Some(self.root_prefix_len),
            file_info,
        )?;

        Ok(Self::FileContext::new(handle, file_size, is_directory))
    }

    fn close(&self, context: Self::FileContext) {
        context.close()
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_attributes: u32,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        // println!("create: {file_name:?}\n");

        let is_directory = create_options & FILE_DIRECTORY_FILE.0 != 0;

        let mut maximum_access = FILE_ACCESS_RIGHTS(if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            MAXIMUM_ALLOWED
        });

        let mut create_options = NTCREATEFILE_CREATE_OPTIONS(create_options)
            & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

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

        let file_attributes = if file_attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            FILE_FLAGS_AND_ATTRIBUTES(file_attributes)
        };

        let security_descriptor = PSECURITY_DESCRIPTOR(
            security_descriptor.map_or(std::ptr::null_mut(), |c| c.as_ptr().cast_mut()),
        );
        let result = lfs::lfs_create_file(
            HANDLE(self.root_handle.handle()),
            file_name,
            maximum_access,
            security_descriptor,
            allocation_size.as_mut(),
            file_attributes,
            FILE_CREATE,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            &extra_buffer,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(e)
                if maximum_access.0 == MAXIMUM_ALLOWED
                    && e.to_ntstatus() == STATUS_INVALID_PARAMETER.0 =>
            {
                lfs::lfs_create_file(
                    HANDLE(self.root_handle.handle()),
                    file_name,
                    maximum_access,
                    security_descriptor,
                    allocation_size.as_mut(),
                    file_attributes,
                    FILE_CREATE,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                    &extra_buffer,
                )
            }
            Err(e) => Err(e),
        }?;

        if let Some(extra_buffer) = extra_buffer
            && extra_buffer_is_reparse_point
        {
            lfs::lfs_fs_control_file(
                HANDLE(handle.handle()),
                FSCTL_SET_REPARSE_POINT,
                Some(extra_buffer),
                None,
            )?;
        }

        let file_size = file_info.as_ref().file_size;
        lfs::lfs_get_file_info(
            HANDLE(handle.handle()),
            Some(self.root_prefix_len),
            file_info,
        )?;

        Ok(Self::FileContext::new(handle, file_size, is_directory))
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
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
        let Some(context) = context else {
            return Ok(());
        };

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
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        let needed_size = if let Some(security_descriptor) = security_descriptor {
            lfs::lfs_get_security(
                context.handle(),
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                PSECURITY_DESCRIPTOR(security_descriptor.as_mut_ptr()),
                security_descriptor.len() as u32,
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
        modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        lfs::lfs_set_security(
            context.handle(),
            security_information,
            PSECURITY_DESCRIPTOR(modification_descriptor.as_mut_ptr()),
        )
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
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
            if replace_file_attributes {
                if file_attributes == 0 {
                    FILE_ATTRIBUTE_NORMAL
                } else {
                    FILE_FLAGS_AND_ATTRIBUTES(file_attributes)
                }
            } else {
                FILE_FLAGS_AND_ATTRIBUTES(file_attributes)
            },
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

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let dir_size = context.size();
        let handle = context.handle();
        let pattern = pattern.map(|p| PCWSTR(p.as_ptr()));
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
                    FileIdBothDirectoryInformation,
                    false,
                    &pattern,
                    restart_scan,
                ) {
                    let mut query_info =
                        query_buffer.as_ptr() as *const FILE_ID_BOTH_DIR_INFORMATION;
                    'inner: loop {
                        // SAFETY: FILE_ID_BOTH_DIR_INFO has FileName as the last VST array member, so it's offset is size_of - 1.
                        // bounds check to ensure we don't go past the edge of the buffer.
                        if query_buffer
                            .as_ptr()
                            .map_addr(|addr| addr.wrapping_add(bytes_transferred))
                            < (query_info as *const _ as *const u8).map_addr(|addr| {
                                addr.wrapping_add(offset_of!(
                                    FILE_ID_BOTH_DIR_INFORMATION,
                                    FileName
                                ))
                            })
                        {
                            break 'once;
                        }
                        Self::copy_query_info_to_dirinfo(query_info, &mut dirinfo)?;
                        dirbuffer.write(&mut dirinfo)?;

                        unsafe {
                            let query_next = addr_of!((*query_info).NextEntryOffset).read();
                            if query_next == 0 {
                                break 'inner;
                            }
                            query_info = (query_info as *const _ as *const u8)
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

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
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
        let new_file_name = &new_file_name[1..].as_slice();
        lfs::lfs_rename(
            self.root_handle.handle(),
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
            creation_time as i64,
            last_access_time as i64,
            last_write_time as i64,
            last_change_time as i64,
        )?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
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

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let mut bytes_transferred = 0;
        let handle = context.handle();
        lfs::lfs_read_file(handle, buffer, offset, &mut bytes_transferred)?;
        Ok(bytes_transferred)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let mut bytes_transferred = 0;
        if constrained_io {
            let fsize = lfs::lfs_get_file_size(context.handle())?;
            if offset >= fsize {
                return Ok(0);
            }

            if offset + buffer.len() as u64 > fsize {
                buffer = &buffer[0..(fsize - offset) as usize]
            }
        }

        lfs::lfs_write_file(context.handle(), buffer, offset, &mut bytes_transferred)?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)?;
        Ok(bytes_transferred)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let vol_info = lfs::lfs_get_volume_info(HANDLE(self.root_handle.handle()))?;
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
                stream_info.stream_size = addr_of!((*query_buffer_cursor).StreamSize).read() as u64;
                stream_info.stream_alloc_size =
                    addr_of!((*query_buffer_cursor).StreamAllocationSize).read() as u64;
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

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let reparse_handle = lfs::lfs_open_file(
            HANDLE(self.root_handle.handle()),
            file_name,
            FILE_ACCESS_RIGHTS(0),
            FILE_OPEN_FOR_BACKUP_INTENT
                | FILE_OPEN_REPARSE_POINT
                | if is_directory {
                    FILE_DIRECTORY_FILE
                } else {
                    NTCREATEFILE_CREATE_OPTIONS(0)
                },
        )?;
        let result = lfs::lfs_fs_control_file(
            HANDLE(reparse_handle.handle()),
            FSCTL_GET_REPARSE_POINT,
            None,
            Some(buffer),
        );

        match result {
            Err(e) if e.to_ntstatus() == STATUS_BUFFER_OVERFLOW.0 => {
                Err(FspError::from(STATUS_BUFFER_TOO_SMALL))
            }
            Err(e) => Err(e),
            Ok(bytes) => Ok(bytes as u64),
        }
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let result = lfs::lfs_fs_control_file(
            context.handle(),
            FSCTL_GET_REPARSE_POINT,
            None,
            Some(buffer),
        );
        match result {
            Err(e) if e.to_ntstatus() == STATUS_BUFFER_OVERFLOW.0 => {
                Err(FspError::from(STATUS_BUFFER_TOO_SMALL))
            }
            Err(e) => Err(e),
            Ok(bytes) => Ok(bytes as u64),
        }
    }

    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
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

    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
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

impl AsyncFileSystemContext for NtPassthroughContext {
    async fn read_async(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let mut bytes_transferred = 0;
        async_io::lfs_read_file_async(context.handle_ref(), buffer, offset, &mut bytes_transferred)
            .await?;
        Ok(bytes_transferred)
    }

    async fn write_async(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let mut bytes_transferred = 0;
        if constrained_io {
            let fsize = lfs::lfs_get_file_size(context.handle())?;
            if offset >= fsize {
                return Ok(0);
            }

            if offset + buffer.len() as u64 > fsize {
                buffer = &buffer[0..(fsize - offset) as usize]
            }
        }

        lfs::async_io::lfs_write_file_async(
            context.handle_ref(),
            buffer,
            offset,
            &mut bytes_transferred,
        )
        .await?;
        lfs::lfs_get_file_info(context.handle(), None, file_info)?;
        Ok(bytes_transferred)
    }

    async fn read_directory_async(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let dir_size = context.size();
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
                if let Ok(bytes_transferred) = lfs::async_io::lfs_query_directory_file_async(
                    context.handle_ref(),
                    &mut query_buffer,
                    FileIdBothDirectoryInformation,
                    false,
                    pattern,
                    restart_scan,
                )
                .await
                {
                    let mut query_info =
                        query_buffer.as_ptr() as *const FILE_ID_BOTH_DIR_INFORMATION;
                    'inner: loop {
                        // SAFETY: FILE_ID_BOTH_DIR_INFO has FileName as the last VST array member, so it's offset is size_of - 1.
                        // bounds check to ensure we don't go past the edge of the buffer.
                        if query_buffer
                            .as_ptr()
                            .map_addr(|addr| addr.wrapping_add(bytes_transferred))
                            < (query_info as *const _ as *const u8).map_addr(|addr| {
                                addr.wrapping_add(offset_of!(
                                    FILE_ID_BOTH_DIR_INFORMATION,
                                    FileName
                                ))
                            })
                        {
                            break 'once;
                        }
                        Self::copy_query_info_to_dirinfo(query_info, &mut dirinfo)?;
                        dirbuffer.write(&mut dirinfo)?;

                        unsafe {
                            let query_next = addr_of!((*query_info).NextEntryOffset).read();
                            if query_next == 0 {
                                break 'inner;
                            }
                            query_info = (query_info as *const _ as *const u8)
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

    fn spawn_task(&self, future: impl Future<Output = ()> + Send + 'static) {
        let _ = self.executor.spawn(future);
    }
}
